use config::CertChainConfig;
use hyper;
use hyper::server::{Server, Request, Response};
use hyper::uri::RequestUri::AbsolutePath;
use hyper::net::Fresh;
use rustc_serialize::json::Json;
use std::io::Read;
use std::sync::{Arc, RwLock, Mutex};
use network;
use network::{NetworkMessage, PayloadFlag};
use blockchain::{Block, Blockchain};
use address;
use address::Address;
use std::ops::Deref;
use transaction::{Transaction, TransactionType};
use std::sync::mpsc::{channel, Receiver};
use hash::MerkleRoot;
use std::thread;
use key;
use secp256k1::key::{SecretKey, PublicKey};

pub fn run(config: CertChainConfig) -> () {
    info!("Starting CertChain daemon.");

    let (txn_pool_tx, txn_pool_rx) = channel();
    let (block_tx, block_rx) = channel();
    let secret_key: SecretKey = key::secret_key_from_string(
        &config.secret_key).unwrap();
    let public_key: PublicKey = key::compressed_public_key_from_string(
        &config.compressed_public_key).unwrap();

    // Listen on the network, and connect to all
    // trusted peers on the network.
    network::listen(txn_pool_tx, block_tx, &config);

    // TODO: Rework peer tx access to eliminate need for mutex.
    let peer_txs = Arc::new(Mutex::new(network::connect_to_peers(&config)));

    let blockchain: Arc<RwLock<Blockchain>>
        = Arc::new(RwLock::new(Blockchain::new()));
    let txn_pool: Arc<RwLock<Vec<Transaction>>>
        = Arc::new(RwLock::new(Vec::new()));

    start_txn_pool_listener(txn_pool.clone(), txn_pool_rx);

    let rpc_port = config.rpc_port;
    let blockchain_refclone = blockchain.clone();
    let txn_pool_refclone = txn_pool.clone();
    let peer_txs_c1 = peer_txs.clone();
    thread::spawn(move || {
        /*
         * TODO: Save the Listening struct returned here
         * and call close() on it once graceful shutdown is supported.
         */
        let _ = Server::http((&"127.0.0.1"[..], rpc_port)).unwrap().handle(
            move |mut req: Request, mut res: Response<Fresh>| {
                match (req.method.clone(), req.uri.clone()) {
                    /*(hyper::Get, AbsolutePath(ref path)) if path == "/blockchain" => {
                        let ref blockchain_ref: Vec<Block> = *blockchain_refclone.read().unwrap();
                        res.send(format!("{}", blockchain_ref.len()).as_bytes()).unwrap();
                    },*/
                    (hyper::Get, AbsolutePath(ref path)) if path == "/txn_pool" => {
                        let ref txn_pool_ref: Vec<Transaction> = *txn_pool_refclone.read().unwrap();
                        res.send(format!("{}", txn_pool_ref.len()).as_bytes()).unwrap();
                    },
                    (hyper::Post, AbsolutePath(ref path)) if path == "/trust_institution" => {
                        let mut req_body = String::new();
                        let _ = req.read_to_string(&mut req_body).unwrap();
                        let req_json = Json::from_str(&req_body[..]).unwrap();
                        let addr: Address = address::from_string(
                                req_json.as_object().unwrap()
                                .get("address").unwrap().as_string().unwrap()).unwrap();
                        info!("Received trust request for address: {}", &addr.to_base58());

                        let txn = Transaction::new(
                            TransactionType::Trust(addr),
                            secret_key.clone(), public_key.clone()).unwrap();

                        // Broadcast trust request to peers.
                        for tx in peer_txs_c1.lock().unwrap().deref() {
                            let mut bytes = Vec::new();
                            txn.serialize(&mut bytes).unwrap();
                            tx.send(NetworkMessage::new(
                                    PayloadFlag::Transaction, bytes)).unwrap();
                        }

                        // Add trust request to this node's txn pool.
                        let ref mut txn_pool: Vec<Transaction>
                                = *txn_pool_refclone.write().unwrap();
                        txn_pool.push(txn);
                    },
                    _ => {
                        *res.status_mut() = hyper::NotFound
                    }
                }
        });
    });

    let peer_txs_c2 = peer_txs.clone();
    loop {
        // Create a block and initialize necessary header fields.
        let mut block = Block::new();
        {
            let ref chain_read = *blockchain.read().unwrap();
            block.header.parent_block_hash = chain_read.active_tip_block_header_hash();
        }
        block.header.nonce = 0;
        block.header.author = address::from_pubkey(&public_key).unwrap();

        // Move all txns in txn pool into block.
        {
            let ref mut txn_pool: Vec<Transaction> =
                *txn_pool.write().unwrap();
            while txn_pool.len() > 0 {
                block.txns.push(txn_pool.pop().unwrap());
            }
        }
        block.header.merkle_root_hash = block.txns.merkle_root();

        info!("Mining block with {} txns; block parent: {:?}; merkle root: {:?}",
            block.txns.len(),
            block.header.parent_block_hash,
            block.header.merkle_root_hash);

        // Search for a header that meets difficulty requirement.
        let mut mined_block = None;
        loop {
            let header_hash = block.header.hash();
            if header_hash[0] == 0
                    && header_hash[1] == 0
                    && header_hash[2] <= 0x87 {
                info!("Mined block; hash is: {:?}", header_hash);
                mined_block = Some(block);
                break;
            }

            if block.header.nonce == u64::max_value() {
                info!("Reached max nonce value; will rebuild block.");
                break;
            }
            block.header.nonce += 1;
        }

        // Add any blocks that have been sent to us while mining;
        // do not block if none have been sent.
        while let Ok(b) = block_rx.try_recv() {
            info!("Received block on block_rx channel from \
                    network; adding to blockchain.");
            blockchain.write().unwrap().add_block(b)
        }

        // Determine if the block we just mined still has the active
        // chain block as its parent; if so, add it to the blockchain,
        // otherwise do nothing with it and start mining again.
        match mined_block {
            Some(b) => {
                let mut is_parent_still_active;
                {
                    let ref chain_read = *blockchain.read().unwrap();
                    is_parent_still_active = b.header.parent_block_hash
                        == chain_read.active_tip_block_header_hash();
                }
                if is_parent_still_active {
                    info!("Parent is still active tip; broadcasting to peers and adding to chain.");

                    // Broadcast block to peers.
                    for tx in peer_txs_c2.lock().unwrap().deref() {
                        let mut bytes = Vec::new();
                        b.serialize(&mut bytes).unwrap();
                        tx.send(NetworkMessage::new(
                                PayloadFlag::Block, bytes)).unwrap();
                    }

                    // Add block to blockchain.
                    blockchain.write().unwrap().add_block(b)
                } else {
                    info!("ACTIVE CHAIN TIP CHANGED; DISCARDING MINED BLOCK.");
                    /*
                     * TODO: Move txns back to the pool for
                     * inclusion in next block.
                     */
                    continue
                }
            },
            /*
             * TODO: Move txns back to the pool for
             * inclusion in next block.
             */
            None => continue
        }

        // Move all txns back to pool.
        /*{
            let ref mut txn_pool: Vec<Transaction> =
                *txn_pool.write().unwrap();
            while block.txns.len() > 0 {
                txn_pool.push(block.txns.pop().unwrap());
            }
            info!("Txn pool size: {}", txn_pool.len());
        }*/
    }
}

pub fn start_txn_pool_listener(txn_pool: Arc<RwLock<Vec<Transaction>>>,
                         rx: Receiver<Transaction>) {
    thread::spawn(move || {
        loop {
            info!("Waiting for txn to arrive on channel...");
            let txn = rx.recv().unwrap();
            info!("Txn arrived on channel.");
            txn_pool.write().unwrap().push(txn);
            info!("Pushed txn to txn pool.");
        }
    });
}

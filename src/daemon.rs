use config::CertChainConfig;
use hyper;
use hyper::server::{Server, Request, Response};
use hyper::uri::RequestUri::AbsolutePath;
use hyper::net::Fresh;
use rustc_serialize::json::Json;
use std::io::Read;
use std::sync::{Arc, RwLock, Mutex};
use network;
use blockchain::{Block, Blockchain};
use address;
use address::Address;
use std::ops::Deref;
use transaction::{Transaction, TransactionType};
use std::sync::mpsc::{channel};
use hash::MerkleRoot;
use std::thread;
use key;
use secp256k1::key::{SecretKey, PublicKey};

pub fn run(config: CertChainConfig) -> () {
    info!("Starting CertChain daemon.");

    let (txn_pool_tx, txn_pool_rx) = channel();
    let secret_key: SecretKey = key::secret_key_from_string(
        &config.secret_key).unwrap();
    let public_key: PublicKey = key::compressed_public_key_from_string(
        &config.compressed_public_key).unwrap();

    // Listen on the network, and connect to all
    // trusted peers on the network.
    network::listen(txn_pool_tx, &config);

    // TODO: Rework peer tx access to eliminate need for mutex.
    let peer_txs = Mutex::new(network::connect_to_peers(&config));

    let blockchain: Arc<RwLock<Blockchain>>
        = Arc::new(RwLock::new(Blockchain::new()));
    let txn_pool: Arc<RwLock<Vec<Transaction>>>
        = Arc::new(RwLock::new(Vec::new()));

    let txn_pool_clone = txn_pool.clone();
    thread::spawn(move || {
        loop {
            info!("Waiting for txn to arrive on channel...");
            let txn = txn_pool_rx.recv().unwrap();
            info!("Txn arrived on channel.");
            txn_pool_clone.write().unwrap().push(txn);
            info!("Pushed txn to txn pool.");
        }
    });

    let rpc_port = config.rpc_port;
    let blockchain_refclone = blockchain.clone();
    let txn_pool_refclone = txn_pool.clone();
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

                        // Add trust request to this node's txn pool.
                        let ref mut txn_pool: Vec<Transaction> = *txn_pool_refclone.write().unwrap();
                        txn_pool.push(Transaction::new(
                            TransactionType::Trust(addr),
                            secret_key.clone(), public_key.clone()).unwrap());

                        // Broadcast trust request to peers.
                        for tx in peer_txs.lock().unwrap().deref() {
                            tx.send(TransactionType::Trust(addr)).unwrap();
                        }
                    },
                    _ => {
                        *res.status_mut() = hyper::NotFound
                    }
                }
        });
    });

    loop {
        // Create a block and initialize necessary header fields.
        let mut block = Block::new();
        {
            let ref chain_read = *blockchain.read().unwrap();
            block.header.parent_block_hash = chain_read.active_tip_block_header_hash();
        }
        block.header.nonce = 0;

        // Move all txns in txn pool into block.
        {
            let ref mut txn_pool: Vec<Transaction> =
                *txn_pool.write().unwrap();
            info!("Txn pool size: {}", txn_pool.len());
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
                    && header_hash[2] <= 0xAF {
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

        match mined_block {
            Some(b) => blockchain.write().unwrap().add_block(b),
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

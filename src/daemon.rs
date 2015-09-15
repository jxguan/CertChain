use config::CertChainConfig;
use hyper;
use hyper::server::{Server, Request, Response};
use hyper::uri::RequestUri::AbsolutePath;
use hyper::net::Fresh;
use rustc_serialize::json::Json;
use std::io::Read;
use std::sync::{Arc, RwLock, Mutex};
use network;
use blockchain::Block;
use address;
use address::Address;
use std::ops::Deref;
use transaction::{Transaction, TransactionType};
use std::sync::mpsc::{channel};
use hash::MerkleRoot;
use std::thread;

pub fn run(config: CertChainConfig) -> () {
    info!("Starting CertChain daemon.");

    let (txn_pool_tx, txn_pool_rx) = channel();

    // Listen on the network, and connect to all
    // trusted peers on the network.
    network::listen(txn_pool_tx, &config);

    // TODO: Rework peer tx access to eliminate need for mutex.
    let peer_txs = Mutex::new(network::connect_to_peers(&config));

    let blockchain: Arc<RwLock<Vec<Block>>>
        = Arc::new(RwLock::new(Vec::new()));
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
                    (hyper::Get, AbsolutePath(ref path)) if path == "/blockchain" => {
                        let ref blockchain_ref: Vec<Block> = *blockchain_refclone.read().unwrap();
                        res.send(format!("{}", blockchain_ref.len()).as_bytes()).unwrap();
                    },
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

    blockchain.write().unwrap().push(Block::genesis_block());
    loop {
        let mut block = Block::new(
            blockchain.read().unwrap().last().unwrap());

        {
            let ref mut txn_pool: Vec<Transaction> =
                *txn_pool.write().unwrap();
            // Move all txns in txn pool into block.
            info!("Txn pool size: {}", txn_pool.len());
            while txn_pool.len() > 0 {
                block.txns.push(txn_pool.pop().unwrap());
            }
        }

        // Initialize the nonce on the block header.
        block.header.nonce = 0;
        block.header.merkle_root_hash = block.txns.merkle_root();
        info!("{} txns in block; merkle root: {:?}", block.txns.len(),
                &block.header.merkle_root_hash);
        thread::sleep_ms(1000);

        {
            let ref mut txn_pool: Vec<Transaction> =
                *txn_pool.write().unwrap();
            // Move all txns back to pool.
            while block.txns.len() > 0 {
                txn_pool.push(block.txns.pop().unwrap());
            }
            info!("Txn pool size: {}", txn_pool.len());
        }
        // Search for a header that meets difficulty requirement.
        //loop {
            // TODO: If matches, add to blockchain.
            // blockchain.write().unwrap().push(block);
        //}
    }
}

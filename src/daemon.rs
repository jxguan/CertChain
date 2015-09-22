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
use transaction;
use transaction::{Transaction, TransactionType, TxnId};
use std::sync::mpsc::{channel, Receiver, Sender};
use hash::{MerkleRoot, DoubleSha256Hash};
use std::thread;
use key;
use secp256k1::key::{SecretKey, PublicKey};
use rustc_serialize::json;
use std::collections::{HashMap, HashSet};

// Used in RCP response; designed to be serializable.
#[derive(RustcEncodable)]
struct TxnSummary {
    pub txn_id: String,
    pub signature_ts: String,
    pub status: String,
    pub revocation_txn_id: String,
}

pub fn run(config: CertChainConfig) -> () {
    info!("Starting CertChain daemon.");

    let (txn_pool_tx, txn_pool_rx) = channel();
    let (block_tx, block_rx) = channel();
    let secret_key: SecretKey = key::secret_key_from_string(
        &config.secret_key).unwrap();
    let public_key: PublicKey = key::compressed_public_key_from_string(
        &config.compressed_public_key).unwrap();
    let institution_addr: Address = address::from_pubkey(&public_key).unwrap();

    // Listen on the network, and connect to all
    // trusted peers on the network.
    network::listen(txn_pool_tx, block_tx, &config);

    // TODO: Rework peer tx access to eliminate need for mutex.
    let peer_txs = Arc::new(Mutex::new(network::connect_to_peers(&config)));

    let blockchain: Arc<RwLock<Blockchain>>
        = Arc::new(RwLock::new(Blockchain::new()));
    let txn_pool: Arc<RwLock<Vec<Transaction>>>
        = Arc::new(RwLock::new(Vec::new()));
    let trust_table: Arc<RwLock<HashMap<String, HashSet<String>>>>
        = Arc::new(RwLock::new(HashMap::new()));
    let certified_table: Arc<RwLock<HashMap<TxnId, (u32, Vec<u8>)>>>
        = Arc::new(RwLock::new(HashMap::new()));
    let revoked_table: Arc<RwLock<HashMap<TxnId, (u32, Vec<u8>)>>>
        = Arc::new(RwLock::new(HashMap::new()));
    let all_txns_set: Arc<RwLock<HashSet<TxnId>>>
        = Arc::new(RwLock::new(HashSet::new()));
    let my_txns_set: Arc<RwLock<HashSet<TxnId>>>
        = Arc::new(RwLock::new(HashSet::new()));
    let pooled_txns_map: Arc<RwLock<HashMap<TxnId, String>>>
        = Arc::new(RwLock::new(HashMap::new()));

    start_txn_pool_listener(txn_pool.clone(), txn_pool_rx);

    let rpc_port = config.rpc_port;
    let blockchain_clone = blockchain.clone();
    let txn_pool_refclone = txn_pool.clone();
    let peer_txs_c1 = peer_txs.clone();
    let trust_table_clone = trust_table.clone();
    let certified_table_clone = certified_table.clone();
    let revoked_table_clone = revoked_table.clone();
    let all_txns_set_clone = all_txns_set.clone();
    let my_txns_set_clone = my_txns_set.clone();
    let pooled_txns_map_clone = pooled_txns_map.clone();
    thread::spawn(move || {
        /*
         * TODO: Save the Listening struct returned here
         * and call close() on it once graceful shutdown is supported.
         */
        let _ = Server::http((&"0.0.0.0"[..], rpc_port)).unwrap().handle(
            move |mut req: Request, mut res: Response<Fresh>| {
                match (req.method.clone(), req.uri.clone()) {
                    (hyper::Get, AbsolutePath(ref path))
                            if path == "/trust_table" => {
                        let ref trust_table
                            = *trust_table_clone.read().unwrap();
                        let trust_json = json::as_pretty_json(trust_table);
                        res.send(format!("{}", trust_json).as_bytes()).unwrap();
                    },
                    (hyper::Post, AbsolutePath(ref path))
                            if path == "/certification_status" => {
                        let mut req_body = String::new();
                        let _ = req.read_to_string(&mut req_body).unwrap();
                        let req_json = Json::from_str(&req_body[..]).unwrap();
                        let txn_id_str = req_json.as_object().unwrap()
                                .get("txn_id").unwrap().as_string().unwrap();
                        let txn_id = transaction::txn_id_from_str(&txn_id_str);
                        match certified_table_clone.read().unwrap().get(&txn_id) {
                            Some(ref cert_tuple) => {
                                match revoked_table_clone.read()
                                        .unwrap().get(&txn_id) {
                                    Some(ref revoked_tuple) => {
                                        res.send(format!("REVOKED")
                                                 .as_bytes()).unwrap();
                                    },
                                    None => {
                                        res.send(format!("CERTIFIED")
                                                 .as_bytes()).unwrap();
                                    }
                                }
                            },
                            None => {
                                res.send(format!("NOT_CERTIFIED")
                                         .as_bytes()).unwrap();
                            }
                        }
                    },
                    (hyper::Get, AbsolutePath(ref path))
                            if path == "/my_txns" => {
                        let mut txns = Vec::new();
                        let pooled_map = pooled_txns_map_clone.read().unwrap();

                        // First, report all cert txns in txn pool.
                        info!("Pooled map len: {}", pooled_map.len());
                        for (txn_id, txn_timestamp) in pooled_map.iter() {
                            txns.push(TxnSummary {
                                txn_id: format!("{:?}", txn_id),
                                signature_ts: format!("{}", txn_timestamp),
                                status: String::from("QUEUED"),
                                revocation_txn_id: String::new()
                            });
                        }

                        // Then, go through all txns authored by
                        // us that have been included in blocks.
                        let my_txns_set = my_txns_set_clone.read().unwrap();
                        for txn_id in my_txns_set.iter() {
                            match certified_table_clone.read()
                                    .unwrap().get(&txn_id) {
                                Some(ref cert_tuple) => {
                                    match revoked_table_clone.read()
                                            .unwrap().get(&txn_id) {
                                        Some(ref revoked_tuple) => {
                                            let (_, ref b) = **revoked_tuple;
                                            let block = Block::deserialize(&b[..]).unwrap();
                                            // Find the revocation transaction in the block.
                                            for b_txn in block.txns().iter() {
                                                if let TransactionType::RevokeCertification(revoked_txn_id) = b_txn.txn_type {
                                                    if revoked_txn_id == *txn_id {
                                                        txns.push(TxnSummary {
                                                            txn_id: format!("{:?}", b_txn.id()),
                                                            signature_ts: format!("{}", b_txn.timestamp),
                                                            status: String::from("REVOKED"),
                                                            revocation_txn_id: format!("{:?}", revoked_txn_id),
                                                        });
                                                        break;
                                                    }
                                                }
                                            }
                                        },
                                        None => {
                                            let (_, ref b) = **cert_tuple;
                                            let block = Block::deserialize(&b[..]).unwrap();
                                            // Find the certification transaction in the block.
                                            for b_txn in block.txns().iter() {
                                                if let TransactionType::Certify(_) = b_txn.txn_type {
                                                    if b_txn.id() == *txn_id {
                                                        txns.push(TxnSummary {
                                                            txn_id: format!("{:?}", b_txn.id()),
                                                            signature_ts: format!("{}", b_txn.timestamp),
                                                            status: String::from("CERTIFIED"),
                                                            revocation_txn_id: String::new(),
                                                        });
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                None => {
                                    /*
                                     * TODO: We should never get here; possibly make
                                     * this a panic.
                                     */
                                    txns.push(TxnSummary {
                                        txn_id: format!("{:?}", txn_id),
                                        signature_ts: String::new(),
                                        status: String::from("NOT PROCESSED"),
                                        revocation_txn_id: String::new(),
                                    });
                                }
                            }
                        }

                        let json = json::as_pretty_json(&txns);
                        res.send(format!("{}", json).as_bytes()).unwrap();
                    }
                    (hyper::Post, AbsolutePath(ref path))
                            if path == "/trust_institution" => {
                        let mut req_body = String::new();
                        let _ = req.read_to_string(&mut req_body).unwrap();
                        let req_json = Json::from_str(&req_body[..]).unwrap();
                        let addr: Address = address::from_string(
                                req_json.as_object().unwrap()
                                .get("address").unwrap().as_string()
                                    .unwrap()).unwrap();
                        info!("Received trust request for \
                              address: {}", &addr.to_base58());
                        broadcast_and_pool_txn(Transaction::new(
                                TransactionType::Trust(addr),
                                secret_key.clone(), public_key.clone()).unwrap(),
                            peer_txs_c1.lock().unwrap().deref(),
                            &mut *txn_pool_refclone.write().unwrap(),
                            &mut *pooled_txns_map_clone.write().unwrap());
                    },
                    (hyper::Post, AbsolutePath(ref path))
                            if path == "/untrust_institution" => {
                        let mut req_body = String::new();
                        let _ = req.read_to_string(&mut req_body).unwrap();
                        let req_json = Json::from_str(&req_body[..]).unwrap();
                        let addr: Address = address::from_string(
                                req_json.as_object().unwrap()
                                .get("address").unwrap().as_string()
                                    .unwrap()).unwrap();
                        info!("Received trust revocation request for \
                              address: {}", &addr.to_base58());
                        broadcast_and_pool_txn(Transaction::new(
                                TransactionType::RevokeTrust(addr),
                                secret_key.clone(), public_key.clone()).unwrap(),
                            peer_txs_c1.lock().unwrap().deref(),
                            &mut *txn_pool_refclone.write().unwrap(),
                            &mut *pooled_txns_map_clone.write().unwrap());
                    },
                    (hyper::Post, AbsolutePath(ref path))
                            if path == "/certify_document" => {
                        let mut req_body = String::new();
                        let _ = req.read_to_string(&mut req_body).unwrap();
                        info!("Received document certification request.");
                        let doc_hash = DoubleSha256Hash::hash(&req_body.as_bytes());
                        let txn = Transaction::new(
                                TransactionType::Certify(doc_hash),
                                secret_key.clone(), public_key.clone()).unwrap();
                        res.send(format!("{:?}", txn.id()).as_bytes()).unwrap();
                        broadcast_and_pool_txn(txn,
                            peer_txs_c1.lock().unwrap().deref(),
                            &mut *txn_pool_refclone.write().unwrap(),
                            &mut *pooled_txns_map_clone.write().unwrap());
                    },
                    (hyper::Post, AbsolutePath(ref path))
                            if path == "/revoke_document" => {
                        let mut req_body = String::new();
                        let _ = req.read_to_string(&mut req_body).unwrap();
                        let req_json = Json::from_str(&req_body[..]).unwrap();
                        let txn_id_str = req_json.as_object().unwrap()
                                .get("txn_id").unwrap().as_string().unwrap();
                        let txn_id = transaction::txn_id_from_str(&txn_id_str);
                        info!("Received document revocation request.");
                        let txn = Transaction::new(
                                TransactionType::RevokeCertification(txn_id),
                                secret_key.clone(), public_key.clone()).unwrap();
                        res.send(format!("{:?}", txn.id()).as_bytes()).unwrap();
                        broadcast_and_pool_txn(txn,
                            peer_txs_c1.lock().unwrap().deref(),
                            &mut *txn_pool_refclone.write().unwrap(),
                            &mut *pooled_txns_map_clone.write().unwrap());
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
            let ref all_txns = all_txns_set.read().unwrap();
            while txn_pool.len() > 0 {
                let txn = txn_pool.pop().unwrap();
                // Discard any txns that have already been included
                // in prior blocks.
                if !all_txns.contains(&txn.id()) {
                    block.add_txn(txn);
                }
            }
        }
        block.header.merkle_root_hash = block.txns().merkle_root();

        info!("Mining block with {} txns; block parent: {:?}; merkle root: {:?}",
            block.txns().len(),
            block.header.parent_block_hash,
            block.header.merkle_root_hash);

        // Search for a header that meets difficulty requirement.
        let mut block_to_add = None;
        let mut block_to_cleanup = None;
        loop {
            // Add any blocks that have been sent to us while mining;
            // do not block if none have been sent.
            if let Ok(b) = block_rx.try_recv() {
                info!("Received block on block_rx channel from \
                        network: {:?}", b.header.hash());
                block_to_add = Some(b);
                break;
            }

            let header_hash = block.header.hash();
            if header_hash[0] == 0
                    && header_hash[1] == 0 {
                    // && header_hash[2] <= 0x87 {
                info!("BLOCK MINED | hash: {:?}", header_hash);
                // Broadcast block to peers.
                for tx in peer_txs_c2.lock().unwrap().deref() {
                    let mut bytes = Vec::new();
                    block.serialize(&mut bytes).unwrap();
                    tx.send(NetworkMessage::new(
                            PayloadFlag::Block, bytes)).unwrap();
                }
                block_to_add = Some(block);
                break;
            }

            if block.header.nonce == u64::max_value() {
                info!("Discarding block; reached max nonce value.");
                block_to_cleanup = Some(block);
                break;
            }

            let ref chain_read = *blockchain.read().unwrap();
            if block.header.parent_block_hash !=
                    chain_read.active_tip_block_header_hash() {
                info!("Discarding block; block's parent is longer active tip.");
                block_to_cleanup = Some(block);
                break;
            }
            block.header.nonce += 1;
        }

        match block_to_add {
            Some(block) => {

            // Add block to blockchain.
            blockchain.write().unwrap().add_block(block,
                    &institution_addr,
                    &mut my_txns_set.write().unwrap(),
                    &mut all_txns_set.write().unwrap(),
                    &mut pooled_txns_map.write().unwrap(),
                    &mut trust_table.write().unwrap(),
                    &mut certified_table.write().unwrap(),
                    &mut revoked_table.write().unwrap());
            },
            None => {
                if let Some(ref mut cleanup_block) = block_to_cleanup {
                    // For all unsuccessfully mined blocks, move their txns back
                    // to the txn pool for inclusion in the next block.
                    let ref mut txn_pool: Vec<Transaction> =
                        *txn_pool.write().unwrap();
                    let ref all_txns = all_txns_set.read().unwrap();
                    while cleanup_block.txns().len() > 0 {
                        let txn = cleanup_block.pop_txn();
                        // Only move the txn back to the pool if it
                        // hasn't already been seen in a block.
                        if !all_txns.contains(&txn.id()) {
                            txn_pool.push(txn);
                        }
                    }
                }
            }
        }
    }
}

fn broadcast_and_pool_txn(txn: Transaction,
        peer_txs: &Vec<Sender<NetworkMessage>>,
        txn_pool: &mut Vec<Transaction>,
        pooled_txn_map: &mut HashMap<TxnId, String>) {

    // Broadcast transaction to peers.
    for tx in peer_txs {
        let mut bytes = Vec::new();
        txn.serialize(&mut bytes).unwrap();
        tx.send(NetworkMessage::new(
                PayloadFlag::Transaction, bytes)).unwrap();
    }

    // If certification txn, Index txn in map for status retrieval in RPC calls
    match txn.txn_type {
        TransactionType::Certify(_) => {
            pooled_txn_map.insert(txn.id(), format!("{}", txn.timestamp));
        },
        _ => ()
    };

    // Add transaction to the provided txn pool.
    txn_pool.push(txn);
}

pub fn start_txn_pool_listener(
        txn_pool: Arc<RwLock<Vec<Transaction>>>,
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

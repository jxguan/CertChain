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
use std::collections::{LinkedList, HashMap, HashSet};

// Used in RPC response; designed to be serializable.
#[derive(RustcEncodable)]
struct TxnSummary {
    pub txn_id: String,
    pub signature_ts: String,
    pub status: String,
    pub revocation_txn_id: String,
}

// Used in RPC response; designed to be serializable.
#[derive(RustcEncodable)]
struct DiplomaValidity {
    pub author_addr: String,
    pub status: String,
    pub latest_txn_id: String,
    pub latest_txn_ts: String,
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
    info!("This node is using address: {}", institution_addr);

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
    let pooled_txns_map: Arc<RwLock<HashMap<TxnId, String>>>
        = Arc::new(RwLock::new(HashMap::new()));

    start_txn_pool_listener(txn_pool.clone(), txn_pool_rx);

    let mut fsm: LinkedList<Option<NetworkMessage>> = LinkedList::new();
    loop {
        match fsm.pop_front() {
            Some(_) => { panic!("TODO: Implement FSM.") },
            None => {
                info!("FSM idling...");
                thread::sleep_ms(1000);
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

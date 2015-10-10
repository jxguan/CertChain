use config::CertChainConfig;
use hyper;
use hyper::server::{Server, Request, Response};
use hyper::uri::RequestUri::AbsolutePath;
use hyper::net::Fresh;
use rustc_serialize::json::Json;
use std::io::Read;
use std::sync::{Arc, RwLock, Mutex};
use network;
use network::{NetPayload};
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
use fsm::{FSM,FSMState};
use secp256k1::key::{SecretKey, PublicKey};
use rustc_serialize::json;
use std::collections::{HashMap, HashSet};

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

    let (net_payload_tx, net_payload_rx) = channel();
    let secret_key: SecretKey = key::secret_key_from_string(
        &config.secret_key).unwrap();
    let public_key: PublicKey = key::compressed_public_key_from_string(
        &config.compressed_public_key).unwrap();
    let institution_addr: Address = address::from_pubkey(&public_key).unwrap();
    info!("This node is using address: {}", institution_addr);

    // Listen on the network, and connect to all
    // trusted peers on the network.
    network::listen(net_payload_tx, &config);

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

    let mut fsm: Arc<RwLock<FSM>>
        = Arc::new(RwLock::new(FSM::new()));
    let fsm_clone = fsm.clone();

    thread::spawn(move || {
        loop {
            let net_payload = net_payload_rx.recv().unwrap();
            debug!("Received payload on channel: {:?}", net_payload);
            match net_payload {
                NetPayload::IdentReq(ref identreq) => {
                    if identreq.is_valid() {
                        fsm_clone.write().unwrap().push_state(
                            FSMState::RespondToIdentReq);
                    }
                }
            }
        }
    });

    loop {
        let next_state = fsm.write().unwrap().pop_state();
        match next_state {
            Some(state) => { panic!("TODO: Transition to state.") },
            None => {
                debug!("FSM idling...");
                thread::sleep_ms(1000);
            }
        }
    }
}

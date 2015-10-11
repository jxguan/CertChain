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
use address::InstAddress;
use std::ops::Deref;
use std::sync::mpsc::{channel, Receiver, Sender};
use hash::{MerkleRoot, DoubleSha256Hash};
use std::thread;
use key;
use fsm::{FSM,FSMState};
use secp256k1::key::{SecretKey, PublicKey};
use rustc_serialize::json;
use std::collections::{HashMap, HashSet};
use network::NetPeer;

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
    let inst_peer = NetPeer::new(
            InstAddress::from_pubkey(&public_key).unwrap(),
            &config.hostname, config.port);
    info!("This node is peering as: {} using pubkey {:?}",
            inst_peer, public_key);

    // Listen on the network for inbound messages.
    network::listen(net_payload_tx, &config);

    /*
     * Connect to each of our peers. TODO: Eventually, this should
     * be limited only to those peers who we want to verify us.
     */
    for p in &config.peers {
        let mut peer = NetPeer::new(InstAddress::from_string(
                &p.inst_addr[..]).unwrap(), &p.hostname, p.port);
        match peer.connect(&inst_peer, &secret_key) {
            Ok(_) => (),
            Err(err) => {
                warn!("{}", format!("{}", err));
            }
        }
    }

    let mut fsm: Arc<RwLock<FSM>>
        = Arc::new(RwLock::new(FSM::new()));
    let fsm_clone = fsm.clone();

    /*
     * The payload rx channel is monitored on a separate thread;
     * any valid messages received on the channel are translated
     * into one or more states for the FSM to transition to.
     */
    thread::spawn(move || {
        loop {
            let net_payload = net_payload_rx.recv().unwrap();
            debug!("Received payload on channel: {:?}", net_payload);
            let mut fsm = fsm_clone.write().unwrap();
            match net_payload {
                NetPayload::IdentReq(identreq) => {
                    fsm.push_state(FSMState::RespondToIdentReq(identreq));
                }
            }
        }
    });

    /*
     * Start the finite state machine, which idles
     * if there are no states to transition to.
     * IMPORTANT: For any states that directly reference
     * network data, do not assume that data is valid.
     * Call the appropriate validity check before using it.
     */
    loop {
        let next_state = fsm.write().unwrap().pop_state();
        match next_state {
            Some(state) => match state {
                FSMState::RespondToIdentReq(identreq) => {
                    match identreq.check_validity(&inst_peer) {
                        Ok(_) => {
                            panic!("TODO: Respond to valid ident req.");
                            /*
                             * TODO: Issue IdentResp with signature.
                             */
                        },
                        Err(err) => panic!("TODO: Log invalid ident req.")
                    }
                }
            },
            None => {
                debug!("FSM idling...");
                thread::sleep_ms(1000);
            }
        }
    }
}

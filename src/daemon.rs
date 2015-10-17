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
use network::NetPeerTable;

pub fn run(config: CertChainConfig) -> () {
    info!("Starting CertChain daemon.");

    let (net_payload_tx, net_payload_rx) = channel();
    let secret_key: SecretKey = key::secret_key_from_string(
        &config.secret_key).unwrap();

    // Listen on the network for inbound messages.
    network::listen(net_payload_tx, &config);

    // Connect to each of our peers.
    // TODO: Only request identity if we want verification of our txns.
    let mut peer_table = NetPeerTable::new(&config);
    for p in &config.peers {
        let peer_inst_addr = InstAddress::from_string(
                &p.inst_addr[..]).unwrap();
        peer_table.register(peer_inst_addr, &p.hostname, p.port);
        peer_table.send_identreq(peer_inst_addr, &secret_key);
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
                },
                NetPayload::IdentResp(identresp) => {
                    fsm.push_state(FSMState::ProcessIdentResp(identresp));
                }
            }
        }
    });

    /*
     * Start the finite state machine, which idles
     * if there are no states to transition to.
     */
    loop {
        let next_state = fsm.write().unwrap().pop_state();
        match next_state {
            Some(state) => match state {
                FSMState::RespondToIdentReq(identreq) => {
                    peer_table.handle_identreq(
                        identreq, &secret_key).unwrap();
                },
                FSMState::ProcessIdentResp(identresp) => {
                    peer_table.process_identresp(identresp).unwrap();
                }
            },
            None => {
                debug!("FSM idling...");
                thread::sleep_ms(1000);
            }
        }
    }
}

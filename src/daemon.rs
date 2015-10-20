use config::CertChainConfig;
use std::sync::{Arc, RwLock};
use network;
use network::{NetPayload};
use address::InstAddress;
use std::sync::mpsc::{channel};
use std::thread;
use key;
use fsm::{FSM,FSMState};
use secp256k1::key::{SecretKey};
use network::NetPeerTable;
use rpc;

pub fn run(config: CertChainConfig) -> () {
    info!("Starting CertChain daemon.");

    let (net_payload_tx, net_payload_rx) = channel();
    let secret_key: SecretKey = key::secret_key_from_string(
        &config.secret_key).unwrap();

    // Listen on the network for inbound messages.
    network::listen(net_payload_tx, &config);

    let fsm = Arc::new(RwLock::new(FSM::new()));
    let peer_table = Arc::new(
        RwLock::new(NetPeerTable::new(&config)));

    // Connect to each of our peers.
    // TODO: Only request identity if we want verification of our txns.
    for p in config.peers.clone() {
        let peer_inst_addr = InstAddress::from_string(
                &p.inst_addr[..]).unwrap();
        let peer_table_c1 = peer_table.clone();
        thread::spawn(move || {
            peer_table_c1.write().unwrap()
                .register(peer_inst_addr, &p.hostname, p.port);
            loop {
                let conn_res = peer_table_c1.write()
                        .unwrap().connect(peer_inst_addr, Some(&secret_key));
                if let Err(err) = conn_res {
                    info!("Unable to connect to {}, will \
                          retry: {}.", peer_inst_addr, err);
                    thread::sleep_ms(3000);
                    continue;
                }
                info!("Successfully connected to {}", peer_inst_addr);
                break;
            }
        });
    }

    // Start the RPC server.
    let fsm_c1 = fsm.clone();
    let peer_table_c3 = peer_table.clone();
    thread::spawn(move || {
        rpc::start(&config, fsm_c1, peer_table_c3);
    });

    /*
     * The payload rx channel is monitored on a separate thread;
     * any valid messages received on the channel are translated
     * into one or more states for the FSM to transition to.
     */
    let fsm_clone = fsm.clone();
    thread::spawn(move || {
        loop {
            let net_payload = net_payload_rx.recv().unwrap();
            //debug!("Received payload on channel: {:?}", net_payload);
            let mut fsm = fsm_clone.write().unwrap();
            match net_payload {
                NetPayload::IdentReq(identreq) => {
                    fsm.push_state(FSMState::RespondToIdentReq(identreq));
                },
                NetPayload::IdentResp(identresp) => {
                    fsm.push_state(FSMState::ProcessIdentResp(identresp));
                },
                NetPayload::VerifierReq(_) => {
                    panic!("TODO: Handle verifier request.");
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
                    match peer_table.write().unwrap().handle_identreq(
                        identreq, &secret_key) {
                        Ok(_) => info!("FSM: sent identreq to peer."),
                        Err(err) => warn!("FSM: unable to send identreq: {}",
                                        err)
                    };
                },
                FSMState::ProcessIdentResp(identresp) => {
                    match peer_table.write().unwrap().
                        process_identresp(identresp) {
                        Ok(_) => info!("FSM: processed identresp."),
                        Err(err) => warn!("FSM: unable to process identresp: {}",
                                          err)
                    }
                },
                FSMState::RequestVerifier(addr) => {
                    match peer_table.write().unwrap().
                        request_verifier(addr, &secret_key) {
                        Ok(_) => info!("FSM: requested verifier."),
                        Err(err) => warn!("FSM: unable to request verifier: {}",
                                          err)
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

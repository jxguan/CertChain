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
use network::NetNodeTable;
use rpc;

pub fn run(config: CertChainConfig) -> () {
    info!("Starting CertChain daemon.");

    let (net_payload_tx, net_payload_rx) = channel();
    let secret_key: SecretKey = key::secret_key_from_string(
        &config.secret_key).unwrap();

    // Listen on the network for inbound messages.
    network::listen(net_payload_tx, &config);

    let fsm = Arc::new(RwLock::new(FSM::new()));
    let node_table = Arc::new(
        RwLock::new(NetNodeTable::new(&config)));

    // Connect to desired nodes.
    // TODO: This should probably only connect to peers (we will connect
    // to subscribers on an on-demand basis).
    // TODO: Only request identity if we want verification of our txns.
    for p in config.nodes.clone() {
        let node_inst_addr = InstAddress::from_string(
                &p.inst_addr[..]).unwrap();
        let node_table_c1 = node_table.clone();
        thread::spawn(move || {
            node_table_c1.write().unwrap()
                .register(node_inst_addr, &p.hostname, p.port);
            loop {
                let conn_res = node_table_c1.write()
                        .unwrap().connect(node_inst_addr, Some(&secret_key));
                if let Err(err) = conn_res {
                    info!("Unable to connect to {}, will \
                          retry: {}.", node_inst_addr, err);
                    thread::sleep_ms(3000);
                    continue;
                }
                info!("Successfully connected to {}", node_inst_addr);
                break;
            }
        });
    }

    // Start the RPC server.
    let fsm_c1 = fsm.clone();
    let node_table_c3 = node_table.clone();
    thread::spawn(move || {
        rpc::start(&config, fsm_c1, node_table_c3);
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
                NetPayload::PeerReq(_) => {
                    panic!("TODO: Handle peer request.");
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
                    match node_table.write().unwrap().handle_identreq(
                        identreq, &secret_key) {
                        Ok(_) => info!("FSM: sent identreq to node."),
                        Err(err) => warn!("FSM: unable to send identreq: {}",
                                        err)
                    };
                },
                FSMState::ProcessIdentResp(identresp) => {
                    match node_table.write().unwrap().
                        process_identresp(identresp) {
                        Ok(_) => info!("FSM: processed identresp."),
                        Err(err) => warn!("FSM: unable to process identresp: {}",
                                          err)
                    }
                },
                FSMState::RequestPeer(addr) => {
                    match node_table.write().unwrap().
                        request_peer(addr, &secret_key) {
                        Ok(_) => info!("FSM: requested peer."),
                        Err(err) => warn!("FSM: unable to request peer: {}",
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

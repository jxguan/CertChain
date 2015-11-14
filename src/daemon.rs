use config::CertChainConfig;
use std::sync::{Arc, RwLock};
use network;
use network::{NetPayload, OnDiskNetNode};
use address::InstAddress;
use std::sync::mpsc::{channel};
use std::thread;
use key;
use fsm::{FSM,FSMState};
use secp256k1::key::{SecretKey};
use network::NetNodeTable;
use rpc;
use serde_json;
use std::fs::File;
use std::io::BufWriter;
use hashchain::Hashchain;

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
    let hashchain = Arc::new(RwLock::new(Hashchain::new()));

    // Connect to known nodes, as serialized to disk during prior execution.
    // TODO: This should probably only connect to pending/approved peers
    // (we will connect to subscribers on an on-demand basis).
    let nodes_file = File::open(&config.path_to("nodes.dat")).unwrap();
    let nodes: Vec<OnDiskNetNode> = serde_json::from_reader(nodes_file).unwrap();
    for p in nodes {
        let node_inst_addr = InstAddress::from_string(
                &p.inst_addr[..]).unwrap();
        let node_table_c1 = node_table.clone();
        thread::spawn(move || {
            node_table_c1.write().unwrap()
                .register(node_inst_addr, &p.hostname, p.port,
                          p.our_peering_approval);
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
    let hashchain_c1 = hashchain.clone();
    let node_table_c3 = node_table.clone();
    let config_c1 = config.clone();
    thread::spawn(move || {
        rpc::start(&config_c1, &secret_key, fsm_c1, hashchain_c1, node_table_c3);
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
                NetPayload::PeerReq(peerreq) => {
                    fsm.push_state(FSMState::HandlePeerReq(peerreq));
                    fsm.push_state(FSMState::SyncNodeTableToDisk);
                },
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
                    match node_table.write().unwrap()
                        .process_identresp(identresp) {
                        Ok(_) => info!("FSM: processed identresp."),
                        Err(err) => warn!("FSM: unable to process identresp: {}",
                                          err)
                    };
                },
                FSMState::RequestPeer(addr) => {
                    match node_table.write().unwrap()
                        .request_peer(addr, &secret_key) {
                        Ok(_) => info!("FSM: requested peer."),
                        Err(err) => warn!("FSM: unable to request peer: {}",
                                          err)
                    };
                },
                FSMState::HandlePeerReq(peerreq) => {
                    match node_table.write().unwrap()
                        .handle_peerreq(peerreq) {
                        Ok(_) => info!("FSM: handled peer request."),
                        Err(err) => warn!("FSM: unable to handle peer req: {}",
                                          err)
                    };
                },
                FSMState::ApprovePeerRequest(addr) => {
                    match node_table.write().unwrap()
                        .approve_peerreq(addr, &secret_key, hashchain.clone()) {
                        Ok(_) => info!("FSM: approved peer request."),
                        Err(err) => warn!("FSM: unable to approve peer \
                                            request: {}", err)
                    };
                },
                FSMState::SyncNodeTableToDisk => {
                    let ref node_table = *node_table.read().unwrap();
                    let mut writer = BufWriter::new(File::create(
                            &config.path_to("nodes.dat")).unwrap());
                    serde_json::to_writer_pretty(&mut writer,
                                                 &node_table.to_disk()).unwrap();
                    info!("FSM: sync'ed node table to disk.");
                }
                FSMState::SyncHashchainToDisk => {
                    let ref hashchain = *hashchain.read().unwrap();
                    let mut writer = BufWriter::new(File::create(
                            &config.path_to("hashchain.dat")).unwrap());
                    serde_json::to_writer_pretty(&mut writer,
                                                 &hashchain).unwrap();
                    info!("FSM: sync'ed hashchain to disk.");
                }
            },
            None => {
                debug!("FSM: processing block queue...");
                {
                    let mut hashchain = hashchain.write().unwrap();
                    let blocks_processed = hashchain.process_queue();
                    if blocks_processed {
                        fsm.write().unwrap().push_state(
                            FSMState::SyncHashchainToDisk);
                    }
                }
                debug!("FSM: idling...");
                thread::sleep_ms(1000);
            }
        }
    }
}

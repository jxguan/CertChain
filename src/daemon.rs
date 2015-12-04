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

    // Read the hashchain from disk or start new chain if none found.
    let hashchain = match File::open(&config.path_to("hashchain.dat")) {
        Ok(file) => {
            let raw: Hashchain = serde_json::from_reader(file).unwrap();
            Arc::new(RwLock::new(raw))
        },
        Err(_) => {
            info!("Unable to open hashchain file; starting new chain.");
            Arc::new(RwLock::new(Hashchain::new(config.get_inst_addr())))
        }
    };

    // Connect to known nodes, as serialized to disk during prior execution.
    // TODO: This should probably only connect to pending/approved peers
    // (we will connect to subscribers on an on-demand basis).
    match File::open(&config.path_to("nodes.dat")) {
        Ok(nodes_file) => {
            let nodes: Vec<OnDiskNetNode> = serde_json::from_reader(
                nodes_file).unwrap();
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
                                .unwrap().connect(
                                    node_inst_addr, Some(&secret_key));
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
        },
        Err(_) =>
            warn!("Unable to open node table file; no nodes will be loaded.")
    };

    // Start the RPC server.
    let fsm_c1 = fsm.clone();
    let hashchain_c1 = hashchain.clone();
    let node_table_c3 = node_table.clone();
    let config_c1 = config.clone();
    thread::spawn(move || {
        rpc::start(&config_c1, &secret_key, fsm_c1, hashchain_c1, node_table_c3);
    });

    /*
     * Monitor the payload rx channel on a separate thread;
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
                NetPayload::SigReq(sigreq) => {
                    fsm.push_state(FSMState::HandleSigReq(sigreq));
                },
                NetPayload::SigResp(sigresp) => {
                    fsm.push_state(FSMState::HandleSigResp(sigresp));
                },
                NetPayload::BlocksReq(blocksreq) => {
                    fsm.push_state(FSMState::HandleBlocksReq(blocksreq));
                },
                NetPayload::BlockManifest(manifest) => {
                    fsm.push_state(FSMState::HandleBlockManifest(manifest));
                }
            }
        }
    });

    // Monitor the block processing queue in the background.
    let fsm_clone2 = fsm.clone();
    let hashchain_clone2 = hashchain.clone();
    let node_table_clone2 = node_table.clone();
    thread::spawn(move || {
        loop {
            {
                let mut hashchain = hashchain_clone2.write().unwrap();
                let blocks_processed = hashchain.process_queue(
                        node_table_clone2.clone(), &secret_key);
                if blocks_processed {
                    fsm_clone2.write().unwrap().push_state(
                        FSMState::SyncHashchainToDisk);
                }
            }
            thread::sleep_ms(1000);
        }
    });

    // Start the FSM.
    loop {
        let next_state = fsm.write().unwrap().pop_state();
        let mut log_state = true;
        let log_str_start = format!(">>> {:?} >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>",
                                    &next_state);
        let log_str_end = format!("<<< {:?} <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<",
                                    &next_state);
        match next_state {
            None | Some(FSMState::IdleForMilliseconds(_)) => log_state = false,
            Some(_) => info!("{}", log_str_start)
        };
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
                FSMState::HandleSigReq(sigreq) => {
                    match node_table.write().unwrap()
                            .handle_sigreq(sigreq, fsm.clone(), &secret_key) {
                        Ok(_) => info!("FSM: handled sigreq."),
                        Err(err) => warn!("FSM: unable to handle sigreq: {}",
                                          err)
                    }
                },
                FSMState::HandleSigResp(sigresp) => {
                    match node_table.write().unwrap()
                            .handle_sigresp(sigresp, fsm.clone()) {
                        Ok(_) => info!("FSM: handled sigresp."),
                        Err(err) => warn!("FSM: unable to handle sigresp: {}",
                                          err)
                    }
                },
                FSMState::QueueNewBlock(actions) => {
                    let ref mut hashchain = *hashchain.write().unwrap();
                    hashchain.queue_new_block(
                        node_table.clone(), actions, &secret_key);
                    info!("FSM: queued new block.");
                },
                FSMState::AddSignatureToProcessingBlock(peer_addr, peer_sig) => {
                    let ref mut hashchain = *hashchain.write().unwrap();
                    hashchain.submit_processing_block_signature(
                        peer_addr, peer_sig);
                    info!("FSM: added signature to processing block.");
                },
                FSMState::HandleBlocksReq(blocks_req) => {
                    let ref hashchain = *hashchain.read().unwrap();
                    hashchain.handle_blocks_req(blocks_req, node_table.clone());
                    info!("FSM: handle blocks request.");
                },
                FSMState::HandleBlockManifest(mf) => {
                    // At this time, we are only concerned about block
                    // manifests for other nodes, not ourself. However,
                    // there is a legitimate use case for handling
                    // block manifests containing our own blocks if
                    // we want to recover our own chain.
                    // TODO: Keep this in mind.
                    let ref mut node_table = *node_table.write().unwrap();
                    match node_table.handle_block_manifest(mf, fsm.clone(),
                            &secret_key) {
                        Ok(_) => info!("FSM: handled block manifest."),
                        Err(err) => warn!("FSM: unable to handle block \
                                           manifeset: {}", err)
                    }
                },
                FSMState::SyncNodeTableToDisk => {
                    let ref node_table = *node_table.read().unwrap();
                    let mut writer = BufWriter::new(File::create(
                            &config.path_to("nodes.dat")).unwrap());
                    serde_json::to_writer_pretty(&mut writer,
                                                 &node_table.to_disk()).unwrap();
                    info!("FSM: sync'ed node table to disk.");
                },
                FSMState::SyncHashchainToDisk => {
                    let ref hashchain = *hashchain.read().unwrap();
                    let mut writer = BufWriter::new(File::create(
                            &config.path_to("hashchain.dat")).unwrap());
                    serde_json::to_writer_pretty(&mut writer,
                                                 &hashchain).unwrap();
                    info!("FSM: sync'ed hashchain to disk.");
                },
                FSMState::SyncReplicaToDisk(inst_addr) => {
                    let ref node_table = *node_table.read().unwrap();
                    node_table.write_replica_to_disk(&inst_addr);
                },
                FSMState::IdleForMilliseconds(ms) => {
                    thread::sleep_ms(ms);
                }
            },
            None => {
                let ref mut fsm = *fsm.write().unwrap();
                fsm.push_state(FSMState::IdleForMilliseconds(1000));
            }
        };
        if log_state {
            info!("{}", log_str_end);
        }
    }
}

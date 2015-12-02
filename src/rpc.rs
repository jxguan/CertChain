use hyper::server::{Server, Request, Response};
use hyper;
use hyper::net::Fresh;
use hyper::uri::RequestUri::AbsolutePath;
use config::CertChainConfig;
use std::sync::{Arc, RwLock};
use network::{NetNodeTable, PeeringApproval};
use rustc_serialize::json;
use address::InstAddress;
use fsm::{FSM, FSMState};
use std::io::Read;
use hash::DoubleSha256Hash;
use std::fs::File;
use std::io::{Write, BufWriter};
use hashchain::{DocumentType, Action, Hashchain};
use secp256k1::key::{SecretKey};
use serde_json;
use serde_json::Value;
use std::collections::HashMap;

const RPC_LISTEN : &'static str = "0.0.0.0";

pub fn start(config: &CertChainConfig,
             our_secret_key: &SecretKey,
             fsm: Arc<RwLock<FSM>>,
             hashchain: Arc<RwLock<Hashchain>>,
             node_table: Arc<RwLock<NetNodeTable>>) {
    info!("Starting RPC server...");
    let rpc_server = Server::http((&RPC_LISTEN[..], config.rpc_port)).unwrap();
    info!("RPC server started on {}:{}.", RPC_LISTEN, config.rpc_port);
    // TODO: Save the Listening struct returned here
    // and call close() on it when graceful shutdown is supported.
    let docs_dir = config.path_to("documents");
    let our_secret_key = our_secret_key.clone();
    let _ = rpc_server.handle(
        move |mut req: Request, mut res: Response<Fresh>| {
            match (req.method.clone(), req.uri.clone()) {
                (hyper::Get, AbsolutePath(ref path))
                    if path == "/network" => {
                    handle_network_req(res, node_table.clone());
                },
                (hyper::Post, AbsolutePath(ref path))
                    if path.len() > 14
                        && &path[0..14] == "/request_peer/" => {
                    handle_peer_request(res, fsm.clone(),
                            node_table.clone(),
                            our_secret_key.clone(), &path[14..]);
                },
                (hyper::Post, AbsolutePath(ref path))
                    if path.len() > 17
                        && &path[0..17] == "/approve_peerreq/" => {
                    approve_peer_req(res, fsm.clone(),
                            node_table.clone(), &path[17..]);
                },
                (hyper::Post, AbsolutePath(ref path))
                    if path.len() > 9
                        && &path[0..9] == "/certify/" => {
                    let params = &path[9..].split("/").collect::<Vec<&str>>();
                    let mut req_body = String::new();
                    req.read_to_string(&mut req_body).unwrap();
                    certify(res, fsm.clone(), hashchain.clone(),
                            &docs_dir, req_body, &params);
                },
                (hyper::Post, AbsolutePath(ref path))
                    if path == "/add_node" => {
                    let mut req_body = String::new();
                    req.read_to_string(&mut req_body).unwrap();
                    add_node(res, node_table.clone(), fsm.clone(),
                            our_secret_key.clone(), req_body);
                },
                (hyper::Post, AbsolutePath(ref path))
                    if path.len() > 13
                        && &path[0..13] == "/remove_node/" => {
                    remove_node(res, fsm.clone(),
                            node_table.clone(), &path[13..]);
                },
                (hyper::Post, AbsolutePath(ref path))
                    if path.len() > 8
                        && &path[0..8] == "/revoke/" => {
                    revoke(res, fsm.clone(), &path[8..]);
                },
                (hyper::Get, AbsolutePath(ref path))
                    if path == "/all_certifications" => {
                    handle_all_certifications_req(res, hashchain.clone());
                },
                (hyper::Get, AbsolutePath(ref path))
                    if path.len() > 30
                        && &path[0..30] == "/certifications_by_student_id/" => {
                    handle_certifications_by_student_id_req(
                        res, hashchain.clone(), &path[30..]);
                },
                (hyper::Get, AbsolutePath(ref path))
                    if path.len() > 10
                        && &path[0..10] == "/document/" => {
                    handle_document_req(res, hashchain.clone(),
                        &docs_dir, &path[10..]);
                },
                (hyper::Post, AbsolutePath(ref path))
                    if path.len() > 13
                        && &path[0..13] == "/end_peering/" => {
                    end_peering(res, hashchain.clone(), fsm.clone(),
                            node_table.clone(), &path[13..]);
                },
                (hyper::Get, AbsolutePath(ref path))
                    if path.len() > 7
                        && &path[0..7] == "/block/" => {
                    handle_block_req(res, hashchain.clone(), &path[7..]);
                },
                _ => *res.status_mut() = hyper::NotFound
            }
        }
    );
}

fn handle_network_req(res: Response<Fresh>,
                      node_table: Arc<RwLock<NetNodeTable>>) {
    let ref node_table = *node_table.read().unwrap();
    let pt_json = format!("{}", json::as_pretty_json(&node_table));
    res.send(pt_json.as_bytes()).unwrap();
}

fn handle_peer_request(res: Response<Fresh>,
                       fsm: Arc<RwLock<FSM>>,
                       node_table: Arc<RwLock<NetNodeTable>>,
                       our_secret_key: SecretKey,
                       addr_param: &str) {

    // Convert the address parameter into an InstAddress.
    let addr = match InstAddress::from_string(addr_param) {
        Ok(addr) => addr,
        Err(_) => {
            res.send("The address provided is not \
                     valid.".as_bytes()).unwrap();
            return;
        }
    };

    // Ensure that we have confirmed this institution's
    // identity.
    let ref mut node_table = *node_table.write().unwrap();
    match node_table.request_peer(addr, &our_secret_key) {
        Ok(_) => {
            // Have the FSM eventually sync node table to disk.
            let ref mut fsm = *fsm.write().unwrap();
            fsm.push_state(FSMState::SyncNodeTableToDisk);
            res.send("OK".as_bytes()).unwrap();
        },
        Err(err) => {
            res.send(format!("An error prevented your peer request from \
                     being submitted: {}.", err).as_bytes()).unwrap();
            return;
        }
    };
}

fn approve_peer_req(res: Response<Fresh>,
                    fsm: Arc<RwLock<FSM>>,
                    node_table: Arc<RwLock<NetNodeTable>>,
                    addr_param: &str) {

    // Convert the address parameter into an InstAddress.
    let addr = match InstAddress::from_string(addr_param) {
        Ok(addr) => addr,
        Err(_) => {
            res.send("The address provided is not \
                     valid.".as_bytes()).unwrap();
            return;
        }
    };

    // Approve the peer request; the callee will handle
    // all further checks and FSM state queueing.
    let ref mut node_table = *node_table.write().unwrap();
    match node_table.approve_peerreq(addr, fsm) {
        Ok(_) => res.send("OK".as_bytes()).unwrap(),
        Err(err) => {
            res.send(format!("{}", err).as_bytes()).unwrap();
            return;
        }
    };
}

fn certify(res: Response<Fresh>,
           fsm: Arc<RwLock<FSM>>,
           hashchain: Arc<RwLock<Hashchain>>,
           docs_dir_path: &String,
           document: String,
           params: &Vec<&str>) {

    // Ensure params are valid.
    if params.len() != 2 {
        res.send("Expected <doctype>/<student_id>.".as_bytes()).unwrap();
        return;
    }

    // Ensure doctype is valid.
    let doctype = match params[0] {
        "Diploma" => DocumentType::Diploma,
        "Transcript" => DocumentType::Transcript,
        _ => {
            res.send("Unexpected doctype.".as_bytes()).unwrap();
            return;
        }
    };

    // Ensure student id is valid.
    let student_id = match params[1].len() {
        0 => {
            res.send("Expected non-empty student ID.".as_bytes()).unwrap();
            return;
        },
        _ => String::from(params[1])
    };


    // Create a certification action for the document.
    let doc_id = DoubleSha256Hash::hash_string(&document);
    info!("Hashed {} to {}", &document, doc_id);
    let action = Action::Certify(doc_id, doctype, student_id);

    // Any block issued by an institution must have at least
    // one signoff peer. This is enforced later, but check it now
    // to give immediate notification to user if this is the case.
    let ref hashchain = *hashchain.read().unwrap();
    if hashchain.get_signoff_peers(&vec![action.clone()]).len() == 0 {
        res.send("You must have at least one peer \
                 to certify documents on the network.".as_bytes()).unwrap();
        return
    }

    // Write the document contents to disk for later retrieval.
    let doc_file = match File::create(format!("{}/{:?}.txt",
                                    docs_dir_path, doc_id)) {
        Ok(f) => f,
        Err(_) => {
            res.send("Failed to create file to store document contents;
                     aborting certification.".as_bytes()).unwrap();
            return;
        }
    };
    let mut writer = BufWriter::new(doc_file);
    match writer.write(&document.as_bytes()[..]) {
        Ok(_) => (),
        Err(_) => {
            res.send("Failed to write document contents to disk;
                     aborting certification.".as_bytes()).unwrap();
            return;
        }
    };

    // Have the FSM queue a new block and sync the queued
    // block to disk.
    let ref mut fsm = *fsm.write().unwrap();
    fsm.push_state(FSMState::QueueNewBlock(vec![action]));
    fsm.push_state(FSMState::SyncHashchainToDisk);

    res.send("OK".as_bytes()).unwrap();
}

fn revoke(res: Response<Fresh>,
                    fsm: Arc<RwLock<FSM>>,
                    docid_param: &str) {
    // Ensure that the provided document ID is valid.
    let docid = match DoubleSha256Hash::from_string(docid_param) {
        Ok(id) => id,
        Err(_) => {
            res.send("Document ID is not valid.".as_bytes()).unwrap();
            return;
        }
    };

    // Create a revocation action for the document.
    let action = Action::Revoke(docid);

    // Have the FSM queue a new block and sync the queued
    // block to disk.
    let ref mut fsm = *fsm.write().unwrap();
    fsm.push_state(FSMState::QueueNewBlock(vec![action]));
    fsm.push_state(FSMState::SyncHashchainToDisk);

    res.send("OK; revocation submitted.".as_bytes()).unwrap();
}

fn handle_all_certifications_req(res: Response<Fresh>,
                      hashchain: Arc<RwLock<Hashchain>>) {
    let ref hashchain = *hashchain.read().unwrap();
    let json = serde_json::to_string_pretty(
        &hashchain.get_certifications(None)).unwrap();
    res.send(json.as_bytes()).unwrap();
}

fn handle_certifications_by_student_id_req(res: Response<Fresh>,
                      hashchain: Arc<RwLock<Hashchain>>,
                      student_id: &str) {
    let ref hashchain = *hashchain.read().unwrap();
    let json = serde_json::to_string_pretty(
        &hashchain.get_certifications(Some(student_id))).unwrap();
    res.send(json.as_bytes()).unwrap();
}

fn handle_document_req(res: Response<Fresh>,
                       hashchain: Arc<RwLock<Hashchain>>,
                       docs_dir_path: &String,
                       doc_id_param: &str) {
    let file_path = format!("{}/{}.txt", docs_dir_path, doc_id_param);
    let mut doc_file = match File::open(&file_path) {
        Ok(file) => file,
        Err(_) => {
            res.send(format!("Unable to open file: {}", file_path)
                     .as_bytes()).unwrap();
            return;
        }
    };

    let mut doc_text = String::new();
    doc_file.read_to_string(&mut doc_text).unwrap();
    let doc_contents: Value = serde_json::from_str(&doc_text).unwrap();
    let ref hashchain = *hashchain.read().unwrap();
    let status_proof = hashchain.get_document_status_proof(
            DoubleSha256Hash::from_string(doc_id_param).unwrap(),
            doc_contents);
    let json = serde_json::to_string_pretty(&status_proof).unwrap();
    res.send(json.as_bytes()).unwrap();
}

fn end_peering(res: Response<Fresh>,
               hashchain: Arc<RwLock<Hashchain>>,
               fsm: Arc<RwLock<FSM>>,
               node_table: Arc<RwLock<NetNodeTable>>,
               addr_param: &str) {

    // Convert the address parameter into an InstAddress.
    let addr = match InstAddress::from_string(addr_param) {
        Ok(addr) => addr,
        Err(_) => {
            res.send("The address provided is not \
                     valid.".as_bytes()).unwrap();
            return;
        }
    };

    // End peering; the callee will handle
    // all further checks and FSM state queueing.
    let ref mut node_table = *node_table.write().unwrap();
    match node_table.end_peering(addr, hashchain, fsm) {
        Ok(_) => res.send("OK".as_bytes()).unwrap(),
        Err(err) => {
            res.send(format!("{}", err).as_bytes()).unwrap();
            return;
        }
    };
}

fn handle_block_req(res: Response<Fresh>,
                       hashchain: Arc<RwLock<Hashchain>>,
                       block_height: &str) {
    let height = match block_height.parse::<usize>() {
        Ok(h) => h,
        Err(_) => {
            res.send("Block height is invalid.".as_bytes()).unwrap();
            return;
        }
    };

    let ref hashchain = *hashchain.read().unwrap();
    match hashchain.get_block(height) {
        None => {
            res.send("Block does not exist.".as_bytes()).unwrap();
            return;
        },
        Some(b) => {
            let json = serde_json::to_string_pretty(&b).unwrap();
            res.send(json.as_bytes()).unwrap();
        }
    }
}

fn add_node(res: Response<Fresh>,
            node_table: Arc<RwLock<NetNodeTable>>,
            fsm: Arc<RwLock<FSM>>,
            our_secret_key: SecretKey,
            body: String) {
    let node: HashMap<String, String> =
        serde_json::from_str(&body).unwrap();

    let hostname = match node.get("hostname") {
        Some(h) => {
            if h.len() == 0 {
                res.send("Expected non-blank hostname.".as_bytes()).unwrap();
                return
            }
            h.clone()
        },
        None => {
            res.send("Expected hostname.".as_bytes()).unwrap();
            return
        }
    };

    let port = match node.get("port") {
        Some(p) => {
            match p.parse::<u16>() {
                Ok(u) => u,
                Err(_) => {
                    res.send("Expected 16-bit port.".as_bytes()).unwrap();
                    return
                }
            }
        },
        None => {
            res.send("Expected port.".as_bytes()).unwrap();
            return
        }
    };

    let address = match node.get("address") {
        Some(a) => {
            match InstAddress::from_string(&a) {
                Ok(addr) => addr,
                Err(_) => {
                    res.send("Invalid address provided.".as_bytes()).unwrap();
                    return
                }
            }
        },
        None => {
            res.send("Expected address.".as_bytes()).unwrap();
            return
        }
    };

    // Register the node.
    let ref mut node_table = *node_table.write().unwrap();
    node_table.register(address, &hostname, port, PeeringApproval::NotApproved);

    // Connect to the node and ask them to prove their identity;
    // for now, we don't care about there
    // being a connection error.
    let _ = node_table.connect(address, Some(&our_secret_key));

    // Have the FSM eventually sync the node table to disk.
    let ref mut fsm = *fsm.write().unwrap();
    fsm.push_state(FSMState::SyncNodeTableToDisk);

    res.send("OK".as_bytes()).unwrap();
}

fn remove_node(res: Response<Fresh>,
            fsm: Arc<RwLock<FSM>>,
            node_table: Arc<RwLock<NetNodeTable>>,
            inst_addr: &str) {
    let addr = match InstAddress::from_string(&inst_addr) {
        Ok(addr) => addr,
        Err(_) => {
            res.send("Invalid address provided.".as_bytes()).unwrap();
            return
        }
    };

    // Remove the node.
    let ref mut node_table = *node_table.write().unwrap();
    match node_table.remove_node(addr) {
        Ok(_) => (),
        Err(err) => {
            res.send(format!("{}", err).as_bytes()).unwrap();
            return
        }
    };

    // Have the FSM eventually sync the node table to disk.
    let ref mut fsm = *fsm.write().unwrap();
    fsm.push_state(FSMState::SyncNodeTableToDisk);

    res.send("OK".as_bytes()).unwrap();
}

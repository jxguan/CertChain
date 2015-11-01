use hyper::server::{Server, Request, Response};
use hyper;
use hyper::net::Fresh;
use hyper::uri::RequestUri::AbsolutePath;
use config::CertChainConfig;
use std::sync::{Arc, RwLock};
use network::NetNodeTable;
use rustc_serialize::json;
use address::InstAddress;
use fsm::{FSM, FSMState};
use std::io::Read;
use hash::DoubleSha256Hash;
use std::fs::File;
use std::io::{Write, BufWriter};
use hashchain::{Action, Hashchain};

const RPC_LISTEN : &'static str = "0.0.0.0";

pub fn start(config: &CertChainConfig,
             fsm: Arc<RwLock<FSM>>,
             hashchain: Arc<RwLock<Hashchain>>,
             node_table: Arc<RwLock<NetNodeTable>>) {
    info!("Starting RPC server...");
    let rpc_server = Server::http((&RPC_LISTEN[..], config.rpc_port)).unwrap();
    info!("RPC server started on {}:{}.", RPC_LISTEN, config.rpc_port);
    // TODO: Save the Listening struct returned here
    // and call close() on it when graceful shutdown is supported.
    let docs_dir = config.path_to("documents");
    let _ = rpc_server.handle(
        move |mut req: Request, mut res: Response<Fresh>| {
            match (req.method.clone(), req.uri.clone()) {
                (hyper::Get, AbsolutePath(ref path))
                    if path == "/network" => {
                    handle_network_req(res, node_table.clone());
                },
                (hyper::Get, AbsolutePath(ref path))
                    if path.len() > 14
                        && &path[0..14] == "/request_peer/" => {
                    handle_peer_req(res, fsm.clone(),
                            node_table.clone(), &path[14..]);
                },
                (hyper::Post, AbsolutePath(ref path))
                    if path.len() > 17
                        && &path[0..17] == "/approve_peerreq/" => {
                    approve_peer_req(res, fsm.clone(),
                            node_table.clone(), &path[17..]);
                },
                (hyper::Post, AbsolutePath(ref path))
                    if path == "/certify" => {
                    let mut req_body = String::new();
                    req.read_to_string(&mut req_body).unwrap();
                    certify(res, hashchain.clone(),
                            &docs_dir, req_body);
                },
                (hyper::Get, AbsolutePath(ref path))
                    if path == "/certifications" => {
                    handle_certifications_req(res, hashchain.clone());
                },
                (hyper::Get, AbsolutePath(ref path))
                    if path.len() > 10
                        && &path[0..10] == "/document/" => {
                    handle_document_req(res, &docs_dir, &path[10..]);
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

fn handle_peer_req(res: Response<Fresh>,
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

    // Ensure that we have confirmed this institution's
    // identity.
    let ref node_table = *node_table.read().unwrap();
    if !node_table.is_confirmed_node(&addr) {
        res.send("The node you specified has not confirmed \
                 their identity.".as_bytes()).unwrap();
        return;
    }

    // Have the FSM eventually send a peer request
    // to the address.
    let ref mut fsm = *fsm.write().unwrap();
    fsm.push_state(FSMState::RequestPeer(addr));
    fsm.push_state(FSMState::SyncNodeTableToDisk);
    res.send("OK; peer request submitted.".as_bytes()).unwrap();
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

    // Ensure that we have confirmed this institution's
    // identity.
    let ref node_table = *node_table.read().unwrap();
    if !node_table.is_confirmed_node(&addr) {
        res.send("The node whose peer request you attempted \
                 to approve has not confirmed \
                 their identity.".as_bytes()).unwrap();
        return;
    }

    // Have the FSM eventually approve the peer request.
    let ref mut fsm = *fsm.write().unwrap();
    fsm.push_state(FSMState::ApprovePeerRequest(addr));
    fsm.push_state(FSMState::SyncNodeTableToDisk);
    res.send("OK; peer request submitted for approval.".as_bytes()).unwrap();
}

fn certify(res: Response<Fresh>,
           hashchain: Arc<RwLock<Hashchain>>,
           docs_dir_path: &String,
           document: String) {

    // First, hash the document to obtain its ID.
    let doc_bytes = &document.as_bytes()[..];
    let doc_id = DoubleSha256Hash::hash(doc_bytes);

    // Second, write the document contents to disk for later retrieval.
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
    match writer.write(doc_bytes) {
        Ok(_) => (),
        Err(_) => {
            res.send("Failed to write document contents to disk;
                     aborting certification.".as_bytes()).unwrap();
            return;
        }
    };

    // Third, create a certification action for the document.
    let action = Action::Certify(doc_id);

    // Fourth and finally, create a new block containing the action; it will
    // be appended to the hashchain and await signature requests
    // from all peers.
    let ref mut hashchain = *hashchain.write().unwrap();
    hashchain.create_block(vec![action]);

    res.send("OK; certification submitted.".as_bytes()).unwrap();
}

fn handle_certifications_req(res: Response<Fresh>,
                      hashchain: Arc<RwLock<Hashchain>>) {
    let ref hashchain = *hashchain.read().unwrap();
    let pt_json = format!("{}", json::as_pretty_json(&hashchain.get_ids()));
    res.send(pt_json.as_bytes()).unwrap();
}

fn handle_document_req(res: Response<Fresh>,
                       docs_dir_path: &String,
                       doc_id_param: &str) {
    let file_path = format!("{}/{}.txt", docs_dir_path, doc_id_param);
    let mut doc_file = match File::open(&file_path) {
        Ok(file) => file,
        Err(err) => {
            res.send(format!("Unable to open file: {}", file_path)
                     .as_bytes()).unwrap();
            return;
        }
    };

    let mut doc_text = String::new();
    doc_file.read_to_string(&mut doc_text).unwrap();
    res.send(doc_text.as_bytes()).unwrap();
}

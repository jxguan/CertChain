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

const RPC_LISTEN : &'static str = "0.0.0.0";

pub fn start(config: &CertChainConfig,
             fsm: Arc<RwLock<FSM>>,
             node_table: Arc<RwLock<NetNodeTable>>) {
    info!("Starting RPC server...");
    let rpc_server = Server::http((&RPC_LISTEN[..], config.rpc_port)).unwrap();
    info!("RPC server started on {}:{}.", RPC_LISTEN, config.rpc_port);
    // TODO: Save the Listening struct returned here
    // and call close() on it when graceful shutdown is supported.
    let _ = rpc_server.handle(
        move |req: Request, mut res: Response<Fresh>| {
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

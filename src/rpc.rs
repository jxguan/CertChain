use hyper::server::{Server, Request, Response};
use hyper;
use hyper::net::Fresh;
use hyper::uri::RequestUri::AbsolutePath;
use config::CertChainConfig;
use std::sync::{Arc, RwLock};
use network::NetPeerTable;
use rustc_serialize::json;
use address::InstAddress;
use fsm::{FSM, FSMState};

const RPC_LISTEN : &'static str = "0.0.0.0";

pub fn start(config: &CertChainConfig,
             fsm: Arc<RwLock<FSM>>,
             peer_table: Arc<RwLock<NetPeerTable>>) {
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
                    handle_network_req(res, peer_table.clone());
                },
                (hyper::Get, AbsolutePath(ref path))
                    if path.len() > 18
                        && &path[0..18] == "/request_verifier/" => {
                    handle_verifier_req(res, fsm.clone(),
                            peer_table.clone(), &path[18..]);
                },
                _ => *res.status_mut() = hyper::NotFound
            }
        }
    );
}

fn handle_network_req(res: Response<Fresh>,
                      peer_table: Arc<RwLock<NetPeerTable>>) {
    let ref peer_table = *peer_table.read().unwrap();
    let pt_json = format!("{}", json::as_pretty_json(&peer_table));
    res.send(pt_json.as_bytes()).unwrap();
}

fn handle_verifier_req(res: Response<Fresh>,
                       fsm: Arc<RwLock<FSM>>,
                       peer_table: Arc<RwLock<NetPeerTable>>,
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
    let ref peer_table = *peer_table.read().unwrap();
    if !peer_table.is_confirmed_peer(&addr) {
        res.send("The peer you specified has not confirmed \
                 their identity.".as_bytes()).unwrap();
        return;
    }

    // Have the FSM eventually send a verifier request
    // to the address.
    let ref mut fsm = *fsm.write().unwrap();
    fsm.push_state(FSMState::RequestVerifier(addr));
    res.send("OK; verifier request submitted.".as_bytes()).unwrap();
}

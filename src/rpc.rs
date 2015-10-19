use hyper::server::{Server, Request, Response};
use hyper;
use hyper::net::Fresh;
use hyper::uri::RequestUri::AbsolutePath;
use config::CertChainConfig;
use std::sync::{Arc, RwLock};
use network::NetPeerTable;
use rustc_serialize::json;

const RPC_LISTEN : &'static str = "0.0.0.0";

pub fn start(config: &CertChainConfig, peer_table: Arc<RwLock<NetPeerTable>>) {
    info!("Starting RPC server...");
    let rpc_server = Server::http((&RPC_LISTEN[..], config.rpc_port)).unwrap();
    info!("RPC server started on {}:{}.", RPC_LISTEN, config.rpc_port);
    // TODO: Save the Listening struct returned here
    // and call close() on it when graceful shutdown is supported.
    let _ = rpc_server.handle(
        move |req: Request, mut res: Response<Fresh>| {
            match (req.method.clone(), req.uri.clone()) {
                (hyper::Get, AbsolutePath(ref path))
                    if path == "/peers" => {
                    let ref peer_table = *peer_table.read().unwrap();
                    let pt_json = format!("{}", json::as_pretty_json(&peer_table));
                    res.send(pt_json.as_bytes()).unwrap();
                },
                _ => *res.status_mut() = hyper::NotFound
            }
        }
    );
}

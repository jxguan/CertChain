use hyper::server::{Server, Request, Response};
use hyper;
use hyper::net::Fresh;
use hyper::uri::RequestUri::AbsolutePath;
use config::CertChainConfig;

const RPC_LISTEN : &'static str = "0.0.0.0";

pub fn start(config: &CertChainConfig) {
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
                    res.send(b"TODO: Return peers.").unwrap();
                },
                _ => *res.status_mut() = hyper::NotFound
            }
        }
    );
}

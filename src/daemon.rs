use config::CertChainConfig;
use hyper;
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::net::Fresh;
use rustc_serialize::{json};
use std::io::Read;
use std::sync::{Arc, RwLock};
use std::thread;
use network;
use network::NetworkMessage;
use blockchain;
use blockchain::Block;

pub fn run(config: CertChainConfig) -> () {
    info!("Starting CertChain daemon.");

    // Listen on the network, and connect to all
    // trusted peers on the network.
    network::listen(&config);
    let peer_txs = network::connect_to_peers(&config);

    let blockchain: Arc<RwLock<Vec<Block>>>
        = Arc::new(RwLock::new(Vec::new()));

    let rpc_port = config.rpc_port;
    let blockchain_refclone = blockchain.clone();
    thread::spawn(move || {
        /*
         * TODO: Save the Listening struct returned here
         * and call close() on it once graceful shutdown is supported.
         */
        let _ = Server::http((&"127.0.0.1"[..], rpc_port)).unwrap().handle(
            move |req: Request, mut res: Response<Fresh>| {
                match req.method {
                    hyper::Get => {
                        let ref blockchain_ref: Vec<Block> = *blockchain_refclone.read().unwrap();
                        let blockchain_json = json::as_pretty_json(blockchain_ref);
                        res.send(format!("{}", blockchain_json).as_bytes()).unwrap();
                    },
                    _ => *res.status_mut() = StatusCode::MethodNotAllowed
                }
        });
    });

    blockchain.write().unwrap().push(blockchain::get_genesis_block());
    let mut placeholder_inc: u8 = 0;
    loop {
        let mut block = blockchain::create_new_block(
            blockchain.read().unwrap().last().unwrap());
        blockchain::mine_block(&mut block);
        for peer_tx in &peer_txs {
            // TODO: Check status.
            let _ = peer_tx.send(NetworkMessage {
                magic: 4096555,
                cmd: [0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E,
                        0x0, 0x0, 0x0, 0x0, 0x0],
                payload_len: 88,
                payload_checksum: 22,
            });
            placeholder_inc += 1;
        }
        blockchain.write().unwrap().push(block);
    }
}

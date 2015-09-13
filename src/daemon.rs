use config::CertChainConfig;
use hyper;
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri::AbsolutePath;
use hyper::net::Fresh;
use rustc_serialize::json;
use rustc_serialize::json::Json;
use std::io::Read;
use std::sync::{Arc, RwLock, Mutex};
use std::thread;
use network;
use network::{NetworkMessage, TrustPayload, Payload, PeerNotice};
use blockchain;
use blockchain::Block;
use address;
use address::Address;
use secp256k1::key::{SecretKey, PublicKey};
use keys;
use std::sync::mpsc::{Sender};
use std::ops::Deref;

pub fn run(config: CertChainConfig) -> () {
    info!("Starting CertChain daemon.");

    // Listen on the network, and connect to all
    // trusted peers on the network.
    network::listen(&config);

    // TODO: Rework peer tx access to eliminate need for mutex.
    let peer_txs = Mutex::new(network::connect_to_peers(&config));

    let blockchain: Arc<RwLock<Vec<Block>>>
        = Arc::new(RwLock::new(Vec::new()));

    let secret_key: SecretKey = keys::secret_key_from_string(
            &config.secret_key).unwrap();
    let public_key: PublicKey = keys::compressed_public_key_from_string(
            &config.compressed_public_key).unwrap();
    info!("Using public key: {:?}", &public_key);

    let rpc_port = config.rpc_port;
    let blockchain_refclone = blockchain.clone();
    thread::spawn(move || {
        /*
         * TODO: Save the Listening struct returned here
         * and call close() on it once graceful shutdown is supported.
         */
        let _ = Server::http((&"127.0.0.1"[..], rpc_port)).unwrap().handle(
            move |mut req: Request, mut res: Response<Fresh>| {
                match (req.method.clone(), req.uri.clone()) {
                    (hyper::Get, _) => {
                        let ref blockchain_ref: Vec<Block> = *blockchain_refclone.read().unwrap();
                        let blockchain_json = json::as_pretty_json(blockchain_ref);
                        res.send(format!("{}", blockchain_json).as_bytes()).unwrap();
                    },
                    (hyper::Post, AbsolutePath(ref path)) if path == "/trust_institution" => {
                        let mut req_body = String::new();
                        req.read_to_string(&mut req_body);
                        let req_json = Json::from_str(&req_body[..]).unwrap();
                        let addr: Address = address::from_string(
                                req_json.as_object().unwrap()
                                .get("address").unwrap().as_string().unwrap()).unwrap();
                        info!("Received trust request for address: {}", &addr.to_base58());
                        for tx in peer_txs.lock().unwrap().deref() {
                            tx.send(PeerNotice::Trust(addr, secret_key.clone(), public_key.clone()));
                        }
                    },
                    _ => {
                        *res.status_mut() = hyper::NotFound
                    }
                }
        });
    });

    blockchain.write().unwrap().push(blockchain::get_genesis_block());
    let mut placeholder_inc: u8 = 0;
    loop {
        let mut block = blockchain::create_new_block(
            blockchain.read().unwrap().last().unwrap());
        blockchain::mine_block(&mut block);
        /*for peer_tx in &peer_txs {
            let _ = peer_tx.send(NetworkMessage {
                magic: 4096555,
                cmd: [0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E,
                        0x0, 0x0, 0x0, 0x0, 0x0],
                payload_len: 88,
                payload_checksum: 22,
            });
            placeholder_inc += 1;
        }*/
        blockchain.write().unwrap().push(block);
    }
}

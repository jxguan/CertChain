use config::CertChainConfig;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use hyper;
use hyper::client::Client;
use hyper::server::{Server, Request, Response};
use hyper::status::StatusCode;
use hyper::net::Fresh;
use rustc_serialize::{json, Encodable};
use std::io::Read;
use std::sync::{Arc, RwLock};
use std::thread;

#[derive(RustcEncodable, RustcDecodable)]
enum TxnOutputAction {
    CERTIFY, REVOKE
}

#[derive(RustcEncodable, RustcDecodable)]
struct Block {
    pub parent_block_hash: String,
    pub nonce: u32,
    pub pubkey_addr_of_creator: String,
    pub txns: Vec<Transaction>,
}

#[derive(RustcEncodable, RustcDecodable)]
struct Transaction {
    pub version: u32,
    pub pubkey_addr: String,
    pub outputs: Vec<TxnOutput>,
}

#[derive(RustcEncodable, RustcDecodable)]
struct TxnOutput {
    pub action: TxnOutputAction,
    pub pubkey_addr: String,
}

pub fn start(config: CertChainConfig) -> () {
    info!("Starting CertChain daemon.");
    info!("Listener port: {}", config.listener_port);
    /*
     * Connect to network of peers.
     */
    listen();

    let blockchain: Arc<RwLock<Vec<Block>>>
        = Arc::new(RwLock::new(Vec::new()));

    let port = "4000";
    let peer_port = "5000";

    let blockchain_refclone = blockchain.clone();
    thread::spawn(move || {
        /*
         * TODO: Save the Listening struct returned here
         * and call close() on it once graceful shutdown is supported.
         */
        let hostname_port = "127.0.0.1:".to_string() + &port[..];
        let _ = Server::http(&hostname_port[..]).unwrap().handle(
            move |mut req: Request, mut res: Response<Fresh>| {
                match req.method {
                    hyper::Get => {
                        let ref blockchain_ref: Vec<Block> = *blockchain_refclone.read().unwrap();
                        let blockchain_json = json::as_pretty_json(blockchain_ref);
                        res.send(format!("{}", blockchain_json).as_bytes()).unwrap();
                    },
                    hyper::Post => {
                        let mut body = String::new();
                        req.read_to_string(&mut body).unwrap();
                        println!("Received data from peer: {}", body);
                    },
                    _ => *res.status_mut() = StatusCode::MethodNotAllowed
                }
        });
    });

    let client = Client::new();
    let hostname_peer_port = "http:////127.0.0.1:".to_string() + &peer_port[..];
    blockchain.write().unwrap().push(get_genesis_block());
    loop {
        let mut block = create_new_block(
            blockchain.read().unwrap().last().unwrap());
        mine_block(&mut block);
        let block_json = json::encode(&block).unwrap();
        match client.post(&hostname_peer_port[..]).body(block_json.as_bytes()).send() {
            Ok(mut resp) => {
                let mut body = String::new();
                resp.read_to_string(&mut body).unwrap();
                println!("Sent data to peer: {}", body);
            },
            Err(err) => {
                println!("Failed to send block to peer: {}", err);
            }
        }
        blockchain.write().unwrap().push(block);
    }
}

pub fn listen() -> () {
    info!("Listening to network...");
}

fn get_genesis_block() -> Block {
    Block {
        parent_block_hash: "000000000000000000000000000000000000000".to_string(),
        nonce: 0,
        pubkey_addr_of_creator: "1L...".to_string(),
        txns: Vec::new(),
    }
}

fn create_new_block(parent_block: &Block) -> Block {
    let txn = Transaction {
        version: 1,
        pubkey_addr: "1L...".to_string(),
        outputs: Vec::new(),
    };
    let mut block = Block {
        parent_block_hash: "000000000000000000000000000000000000000".to_string(),
        nonce: 0,
        pubkey_addr_of_creator: "1L...".to_string(),
        txns: Vec::new(),
    };

    // Compute and store the parent block's hash.
    let block_json = json::encode(parent_block).unwrap();
    let mut parent_block_double_sha256: Sha256 = double_sha256(&block_json[..]);
    block.parent_block_hash = parent_block_double_sha256.result_str();

    block.txns.push(txn);
    block
}

fn mine_block(block: &mut Block) -> () {
    println!("Mining block...");
    let mut next_nonce : u32 = 0;
    loop {
        block.nonce = next_nonce;

        /*
         * TODO:
         *  - Hash raw bytes of *header only* rather than JSON string representation.
         */
        let block_json = json::encode(block).unwrap();
        let mut double_sha256: Sha256 = double_sha256(&block_json[..]);

        let sha256_num_bytes = double_sha256.output_bytes();
        let mut digest_vec: Vec<u8> = vec!(0u8; sha256_num_bytes);
        let mut digest_bytes: &mut [u8] = &mut digest_vec[..];
        double_sha256.result(&mut digest_bytes);

        if digest_bytes[0] == 0x0
            && digest_bytes[1] == 0x0 {
            println!("Block mined.");
            println!("{}", json::encode(block).unwrap());
            println!("Nonce: {}", next_nonce);
            println!("Block hash: {}", double_sha256.result_str());
            /*for i in sha256_twice_arr.iter() {
                println!("{}", i);
            }*/
            println!("");
            return;
        }
        next_nonce += 1;
    }
}

fn double_sha256(input: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.reset();
    hasher.input_str(input);
    let sha256_once = hasher.result_str();

    hasher.reset();
    hasher.input_str(&sha256_once[..]);
    hasher
}

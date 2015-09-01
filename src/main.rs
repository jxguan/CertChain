extern crate hyper;
extern crate crypto;
extern crate rustc_serialize;
extern crate getopts;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rustc_serialize::{json, Encodable};
use hyper::Server;
use hyper::server::Request;
use hyper::server::Response;
use hyper::net::Fresh;
use std::thread;
use std::sync::{Arc, RwLock};
use std::env;
use getopts::Options;

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

/*
 * TODO:
 *  - Hash raw bytes of *header only* rather than JSON string representation.
 */
fn main() {

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("p", "port", "set HTTP comm port", "PORT");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m },
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let port = match matches.opt_str("p") {
        Some(p) => { p },
        None => { panic!("You must provide a port number; use -p or --port.") }
    };

    let blockchain: Arc<RwLock<Vec<Block>>>
        = Arc::new(RwLock::new(Vec::new()));

    let blockchain_refclone = blockchain.clone();
    thread::spawn(move || {
        /*
         * TODO: Save the Listening struct returned here
         * and call close() on it once graceful shutdown is supported.
         */
        let hostname_port = "127.0.0.1:".to_string() + &port[..];
        let _ = Server::http(&hostname_port[..]).unwrap().handle(
            move |_: Request, res: Response<Fresh>| {
                let ref blockchain_ref: Vec<Block> = *blockchain_refclone.read().unwrap();
                let blockchain_json = json::as_pretty_json(blockchain_ref);
                res.send(format!("{}", blockchain_json).as_bytes()).unwrap();
        });
    });

    blockchain.write().unwrap().push(get_genesis_block());
    loop {
        let mut block = create_new_block(
            blockchain.read().unwrap().last().unwrap());
        mine_block(&mut block);
        blockchain.write().unwrap().push(block);
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
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

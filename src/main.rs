extern crate hyper;
extern crate crypto;
extern crate rustc_serialize;

use std::io::Write;
use hyper::Server;
use hyper::server::Request;
use hyper::server::Response;
use hyper::net::Fresh;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rustc_serialize::{json, Encodable};

#[derive(RustcEncodable, RustcDecodable)]
enum TXN_OUTPUT_ACTION {
    CERTIFY, REVOKE
}

#[derive(RustcEncodable, RustcDecodable)]
struct Block {
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
    pub action: TXN_OUTPUT_ACTION,
    pub pubkey_addr: String,
}

fn hello(_: Request, res: Response<Fresh>) {
    //res.send(hex.as_bytes()).unwrap();
}

/*
 * TODO:
 *  - Create genesis block.
 *  - Add previous block hash field to block header.
 *  - Parameterize proof-of-work difficulty.
 *  - Hash raw bytes rather than JSON string representation.
 */
fn main() {
    let txn = Transaction {
        version: 1,
        pubkey_addr: "1L...".to_string(),
        outputs: Vec::new(),
    };
    let mut block = Block {
        nonce: 0,
        pubkey_addr_of_creator: "1L...".to_string(),
        txns: Vec::new(),
    };
    block.txns.push(txn);

    let mut hasher = Sha256::new();
    let mut next_nonce : u32 = 0;
    loop {
        block.nonce = next_nonce;
        let block_json = json::encode(&block).unwrap();

        hasher.reset();
        hasher.input_str(&block_json[..]);
        let sha256_once = hasher.result_str();

        hasher.reset();
        hasher.input_str(&sha256_once[..]);
        let sha256_twice = hasher.result_str();

        let sha256_num_bytes = hasher.output_bytes();
        let mut sha256_twice_vec: Vec<u8> = vec!(0u8; sha256_num_bytes);
        let mut sha256_twice_arr = &mut sha256_twice_vec[..];
        hasher.result(&mut sha256_twice_arr);

        if (sha256_twice_arr[0] == 0x0
            && sha256_twice_arr[1] == 0x0) {
            println!("Nonce: {}", next_nonce);
            println!("Block hash: {}", hasher.result_str());
            for i in sha256_twice_arr.iter() {
                println!("{}", i);
            }
            println!("");
            break;
        }
        next_nonce += 1;
    }

    //println!("{:?}", json::encode(&block));
//    Server::http("127.0.0.1:3000").unwrap().handle(hello);
}

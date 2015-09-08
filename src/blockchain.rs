use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rustc_serialize::{json, Encodable};

#[derive(RustcEncodable, RustcDecodable)]
pub enum TxnOutputAction {
    CERTIFY, REVOKE
}

#[derive(RustcEncodable, RustcDecodable)]
pub struct Block {
    pub parent_block_hash: String,
    pub nonce: u32,
    pub pubkey_addr_of_creator: String,
    pub txns: Vec<Transaction>,
}

#[derive(RustcEncodable, RustcDecodable)]
pub struct Transaction {
    pub version: u32,
    pub pubkey_addr: String,
    pub outputs: Vec<TxnOutput>,
}

#[derive(RustcEncodable, RustcDecodable)]
pub struct TxnOutput {
    pub action: TxnOutputAction,
    pub pubkey_addr: String,
}

pub fn get_genesis_block() -> Block {
    Block {
        parent_block_hash: "000000000000000000000000000000000000000".to_string(),
        nonce: 0,
        pubkey_addr_of_creator: "1L...".to_string(),
        txns: Vec::new(),
    }
}

pub fn create_new_block(parent_block: &Block) -> Block {
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

pub fn mine_block(block: &mut Block) -> () {
    info!("Mining block...");
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
            info!("Block mined: {}", json::encode(block).unwrap());
            //info!("Nonce: {}", next_nonce);
            //info!("Block hash: {}", double_sha256.result_str());
            /*for i in sha256_twice_arr.iter() {
                println!("{}", i);
            }
            println!("");*/
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


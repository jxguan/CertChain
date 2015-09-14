use transaction::Transaction;
use hash::DoubleSha256Hash;

#[derive(Debug)]
pub struct Block {
    pub magic: u32,
    pub header: BlockHeader,
    pub txn_count: u32,
    pub txns: Vec<Transaction>
}

#[derive(Debug)]
pub struct BlockHeader {
    pub version: u32,
    pub parent_block_hash: DoubleSha256Hash,
    pub merkle_root_hash: DoubleSha256Hash,
    pub timestamp: u32,
    pub nonce: u64,     // TODO: Using u64 to prevent overflows for now.
}

impl BlockHeader {
    pub fn new() -> BlockHeader {
        BlockHeader {
            version: 0,
            parent_block_hash: DoubleSha256Hash::blank(),
            merkle_root_hash: DoubleSha256Hash::blank(),
            timestamp: 0,
            nonce: 0,
        }
    }
}

impl Block {
    pub fn new(parent_block: &Block) -> Block {
        Block {
            magic: 0,
            header: BlockHeader::new(),
            txn_count: 0,
            txns: Vec::new(),
        }
    }

    pub fn genesis_block() -> Block {
        Block {
            magic: 0xFFFF,
            header: BlockHeader::new(),
            txn_count: 0,
            txns: Vec::new(),
        }
    }
}

pub fn mine_block(block: &mut Block) -> () {
    info!("Mining block...");
    let mut next_nonce : u64 = 0;
    loop {
        block.header.nonce = next_nonce;
        next_nonce += 1;
    }
}

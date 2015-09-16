use transaction::Transaction;
use hash::DoubleSha256Hash;
use std::collections::HashMap;
use std::ptr;
use time;
use std::io::{Result, Write, Read};
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use address;
use address::Address;

type BlockTree = HashMap<DoubleSha256Hash, Box<BlockchainNode>>;
type NodePtr = *const BlockchainNode;

#[derive(Debug)]
pub struct Blockchain {
    table: BlockTree,
    active_tip: NodePtr,
}

#[derive(Debug)]
pub struct BlockchainNode {
    pub block: Block,
    pub height: u32,
    prev: NodePtr,
    next: Vec<NodePtr>,
}

impl Blockchain {
    pub fn new() -> Blockchain {
        let genesis_block = Block::genesis_block();
        let genesis_block_header_hash = genesis_block.header.hash();
        info!("Genesis block header hash: {:?}", &genesis_block_header_hash);
        let genesis_block_node = Box::new(BlockchainNode {
            block: genesis_block,
            height: 0,
            prev: ptr::null(),
            next: Vec::new(),
        });
        let genesis_block_node_ptr = &*genesis_block_node as NodePtr;
        Blockchain {
            table: {
                let mut table = HashMap::new();
                table.insert(genesis_block_header_hash, genesis_block_node);
                table
            },
            active_tip: genesis_block_node_ptr
        }
    }

    pub fn active_tip_block_header_hash(&self) -> DoubleSha256Hash {
        unsafe {
            let ref active_tip_node = *self.active_tip;
            active_tip_node.block.header.hash()
        }
    }

    pub fn add_block(&mut self, block: Block) {

        // If the block is already in the table, no need to add it.
        let block_header_hash = block.header.hash();
        if self.table.contains_key(&block_header_hash) {
            info!("Block is already in table, skipping.");
            return
        }

        let parent_block_hash = block.header.parent_block_hash;
        let mut block_node = Box::new(BlockchainNode {
            block: block,
            height: 0,
            prev: ptr::null(),
            next: Vec::new(),
        });

        // Lookup the parent; if we don't have it, we need
        // to get it from peers.
        match self.table.get_mut(&parent_block_hash) {
            Some(parent) => {
                parent.next.push(&*block_node as NodePtr);
                block_node.prev = &**parent as NodePtr;
                block_node.height = parent.height + 1;
            },
            None => panic!("PARENT OF BLOCK DOESNT EXIST IN BLOCKCHAIN; TODO: get from peers.")
        };

        // If the block's height is greater than that of the height
        // of the current active chain tip, point to the block.
        unsafe {
            if block_node.height > (*self.active_tip).height {
                let block_node_ptr = &*block_node as NodePtr;
                self.active_tip = block_node_ptr;
                info!("Active tip now has height of: {}", (*self.active_tip).height);
            }
        }
        let do_scan = block_node.height % 10 == 0;

        // Add the block to the table.
        self.table.insert(block_header_hash, block_node);

        if do_scan {
            let mut branch_count = 0;
            for (_, val) in self.table.iter() {
                if val.next.len() == 0 {
                    branch_count += 1;
                }
            }
            info!("BLOCK TABLE SCAN: {} branches exist.", branch_count);
        }
    }
}

#[derive(Debug)]
pub struct BlockHeader {
    pub version: u32,
    pub parent_block_hash: DoubleSha256Hash,
    pub merkle_root_hash: DoubleSha256Hash,
    pub timestamp: i64,
    pub nonce: u64,     // TODO: Using u64 to prevent overflows for now.
    pub author: Address,
}

impl BlockHeader {
    pub fn new() -> BlockHeader {
        BlockHeader {
            version: 1,
            parent_block_hash: DoubleSha256Hash::blank(),
            merkle_root_hash: DoubleSha256Hash::blank(),
            timestamp: time::get_time().sec,
            nonce: 0,
            author: Address::blank(),
        }
    }

    pub fn hash(&self) -> DoubleSha256Hash {
        let mut bytes = Vec::new();
        self.serialize(&mut bytes).unwrap();
        DoubleSha256Hash::hash(&bytes[..])
    }

    pub fn deserialize<R: Read>(mut reader: R) -> Result<BlockHeader> {
        Ok(BlockHeader {
            version: try!(reader.read_u32::<BigEndian>()),
            parent_block_hash: try!(DoubleSha256Hash::deserialize(&mut reader)),
            merkle_root_hash: try!(DoubleSha256Hash::deserialize(&mut reader)),
            timestamp: try!(reader.read_i64::<BigEndian>()),
            nonce: try!(reader.read_u64::<BigEndian>()),
            author: try!(address::deserialize(&mut reader))
        })
    }

    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<()> {
        try!(writer.write_u32::<BigEndian>(self.version));
        try!(self.parent_block_hash.serialize(&mut writer));
        try!(self.merkle_root_hash.serialize(&mut writer));
        try!(writer.write_i64::<BigEndian>(self.timestamp));
        try!(writer.write_u64::<BigEndian>(self.nonce));
        try!(self.author.serialize(&mut writer));
        Ok(())
    }
}

#[derive(Debug)]
pub struct Block {
    pub magic: u32,
    pub header: BlockHeader,
    pub txn_count: u32,
    pub txns: Vec<Transaction>
}

impl Block {
    pub fn new() -> Block {
        Block {
            magic: 0xABCD1234,
            header: BlockHeader::new(),
            txn_count: 0,
            txns: Vec::new(),
        }
    }

    // REMEMBER: The data returned here must be the same
    // on all clients; TODO: serialize the raw bytes and
    // hard-code here, then create Block/BlockHeader from
    // those bytes.
    pub fn genesis_block() -> Block {
        let mut header = BlockHeader::new();
        header.timestamp = 1442353876;
        Block {
            magic: 0xABCD1234,
            header: header,
            txn_count: 0,
            txns: Vec::new(),
        }
    }

    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<()> {
        try!(writer.write_u32::<BigEndian>(self.magic));
        try!(self.header.serialize(&mut writer));
        try!(writer.write_u32::<BigEndian>(self.txn_count));
        for txn in &self.txns {
            try!(txn.serialize(&mut writer));
        }
        Ok(())
    }

    pub fn deserialize<R: Read>(mut reader: R) -> Result<Block> {
        let magic = try!(reader.read_u32::<BigEndian>());
        let header = try!(BlockHeader::deserialize(&mut reader));
        let txn_count = try!(reader.read_u32::<BigEndian>());
        Ok(Block {
            magic: magic,
            header: header,
            txn_count: txn_count,
            txns: {
                let mut txns = Vec::new();
                for _ in 0..txn_count {
                    txns.push(try!(Transaction::deserialize(&mut reader)));
                }
                txns
            }
        })
    }
}

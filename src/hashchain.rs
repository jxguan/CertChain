use hash::DoubleSha256Hash;
use address::InstAddress;
use serde::{ser, de};
use std::collections::{HashSet, HashMap};
use std::collections::vec_deque::VecDeque;
use time;
use std::sync::{Arc, RwLock};
use network::{NetNodeTable, SignatureRequest};
use signature::RecovSignature;
use secp256k1::key::SecretKey;
use common::ValidityErr;
use serde::ser::Serialize;

pub type DocumentId = DoubleSha256Hash;

#[derive(Serialize, Deserialize)]
pub struct Hashchain {
    chain: HashMap<DoubleSha256Hash, ChainNode>,
    head_node: Option<DoubleSha256Hash>,
    tail_node: Option<DoubleSha256Hash>,
    processing_block: Option<Block>,
    queued_blocks: VecDeque<Block>,
}

#[derive(Serialize, Deserialize)]
pub struct ChainNode {
    block: Block,
    next_block: Option<DoubleSha256Hash>
}

#[derive(Serialize, Deserialize, RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    actions: Vec<Action>,
    author_signature: RecovSignature
}

#[derive(Serialize, Deserialize, RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct BlockHeader {
    timestamp: i64,
    pub parent: DoubleSha256Hash,
    pub author: InstAddress,
}

#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub enum DocumentType {
    Diploma,
    Transcript
}

#[derive(Serialize, Deserialize, RustcEncodable, RustcDecodable, Clone, Debug)]
pub enum Action {
    Certify(DocumentId, DocumentType, String),
    AddPeer(InstAddress, String, u16)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DocumentSummary {
    doc_id: DocumentId,
    doc_type: DocumentType,
    student_id: String,
    cert_timestamp: Option<i64>,
    rev_timestamp: Option<i64>,
}

pub enum AppendErr {
    MissingBlocksSince(DoubleSha256Hash),
    BlockAlreadyInChain,
    BlockParentAlreadyClaimed,
    ChainStateCorrupted,
}

impl Hashchain {
    pub fn new() -> Hashchain {
        Hashchain {
            chain: HashMap::new(),
            head_node: None,
            tail_node: None,
            processing_block: None,
            queued_blocks: VecDeque::new(),
        }
    }

    /// Determines if the provided block can be appended to the hashchain.
    pub fn is_block_eligible_for_append(
            &self, block: &Block) -> Result<(), AppendErr> {

        // Is this block already present in the chain?
        if self.chain.contains_key(&block.header.hash()) {
            return Err(AppendErr::BlockAlreadyInChain)
        }

        if block.header.parent == DoubleSha256Hash::genesis_block_parent_hash() {
            if self.head_node == None
                && self.tail_node == None
                && self.chain.len() == 0 {
                Ok(())
            } else {
                Err(AppendErr::ChainStateCorrupted)
            }
            // TODO: Move the following lines to the actual append method.
            //let chain_node = ChainNode::new(block);
            //self.head_node = Some(chain_node.block.header.hash());
            //self.tail_node = Some(chain_node.block.header.hash());
            //self.chain.insert(chain_node.block.header.hash(), chain_node);
        } else {
            panic!("TODO: Handle non-genesis block.");
        }
    }

    /// Queues a new block for signing, but importantly, signature
    /// requests are not sent by this method. When the FSM transitions
    /// to process the queue, signatures will be sent once all prior
    /// queued blocks have been signed and finalized.
    pub fn queue_new_block(&mut self,
                           our_inst_addr: InstAddress,
                           actions: Vec<Action>,
                           our_secret_key: &SecretKey) {
        self.queued_blocks.push_back(
            Block::new(our_inst_addr,
                       self.tail_node,
                       actions,
                       &our_secret_key));
    }

    /// Determines the peers whose signatures are required for new_block
    /// to be added to the hashchain. This includes existing peers and peers
    /// being added in new_block, and excludes peers being removed in
    /// new_block.
    fn get_signoff_peers(&self, new_block: &Block) -> HashSet<InstAddress> {

        // Existing peers must sign off on new_block.
        let mut peers = HashSet::new();
        for (_, chain_node) in self.chain.iter() {
            for action in chain_node.block.actions.iter() {
                match *action {
                    Action::AddPeer(inst_addr, _, _) => {
                        peers.insert(inst_addr);
                    },
                    Action::Certify(_, _, _) => (),
                    /*
                     * TODO: When adding RemovePeer to this
                     * statement, remove from peer set.
                     */
                }
            }
        }

        // New peers must sign off on new block, but
        // removed peers do not.
        for action in new_block.actions.iter() {
            match *action {
                Action::AddPeer(inst_addr, _, _) => {
                    peers.insert(inst_addr);
                },
                Action::Certify(_, _, _) => (),
                /*
                 * TODO: When adding RemovePeer to this
                 * statement, remove from peer set.
                 */
            }
        }
        peers
    }

    /// At any given time, at most one block is processing.
    /// Blocks are processed once they are reached in the queue.
    /// This implies that at any given time, signature requests
    /// are in flight or awaiting receipt for the processing block only;
    /// to leave the processing state, and thus process other blocks in
    /// the queue, we either need all required signatures, or
    /// processing of the block must be aborted.
    /// Returns true if hashchain state was modified (and thus
    /// disk sync required), false otherwise.
    pub fn process_queue(&mut self,
                         node_table: Arc<RwLock<NetNodeTable>>,
                         our_secret_key: &SecretKey) -> bool {

        let mut processed_block = false;
        match self.processing_block {
            None => {
                // Start processing the next queued block if one exists,
                // otherwise, simply return.
                let block_to_process = match self.queued_blocks.pop_front() {
                    Some(b) => {
                        info!("Elevating block {} from queue for processing.",
                              b.header.hash());
                        b
                    },
                    None => {
                        debug!("HCHAIN: No queued blocks; nothing to process.");
                        return false
                    }
                };

                // Broadcast signature requests to all signoff peers.
                let signoff_peers = self.get_signoff_peers(
                        &block_to_process);
                for peer_addr in signoff_peers {
                    let sigreq = SignatureRequest::new(peer_addr,
                            block_to_process.clone(), &our_secret_key);
                    match node_table.write().unwrap().send_sigreq(sigreq) {
                        Ok(()) => info!("Siqreq sent to {}", peer_addr),
                        Err(_) => {
                            panic!("TODO: What to do if sigreq can't be sent
                                    to a peer? - need to set flag somewhere
                                    so admin can remove peer if necessary.");
                        }
                    }
                }
                self.processing_block = Some(block_to_process);

                // Hashchain state modified, sync to disk.
                return true;
            },
            Some(ref block) => {
                if block.is_valid() {
                    info!("HCHAIN: Finalizing queued block.");
                    self.chain.insert(block.header.hash(),
                        ChainNode::new(block.clone()));
                    processed_block = true;
                } else {
                    info!("HCHAIN: Block is not yet valid.");
                }
            }
        };

        // We do this here rather than within the match stmt because
        // we cannot modify self.processing_block when it is borrowed.
        if processed_block {
            self.processing_block = None;
        }
        processed_block
    }

    pub fn get_certifications(&self,
                optional_student_id: Option<&str>) -> Vec<DocumentSummary> {
        let mut summaries = Vec::new();
        for (_, chain_node) in self.chain.iter() {
            for action in chain_node.block.actions.iter() {
                match *action {
                    Action::Certify(_, _, ref sid) => {
                        match optional_student_id {
                            Some(id) => {
                                if id == sid {
                                    summaries.push(
                                        DocumentSummary::new(&chain_node.block,
                                                             action.clone()))
                                }
                            }, None => summaries.push(
                                            DocumentSummary::new(&chain_node
                                                        .block, action.clone()))
                        };
                    },
                    Action::AddPeer(_, _, _) => {
                        continue;
                    }
                }
            }
        }
        summaries
    }
}

impl ChainNode {
    fn new(block: Block) -> ChainNode {
        ChainNode {
            block: block,
            next_block: None
        }
    }
}

impl Block {
    fn new(our_inst_addr: InstAddress,
           parent: Option<DoubleSha256Hash>,
           actions: Vec<Action>,
           our_secret_key: &SecretKey) -> Block {
        let header = BlockHeader::new(parent, our_inst_addr);
        let header_hash = header.hash();
        Block {
            header: header,
            actions: actions,
            author_signature: RecovSignature::sign(
                &header_hash, &our_secret_key)
        }
    }

    pub fn is_authors_signature_valid(&self) -> Result<(), ValidityErr> {
        let expected_msg = self.header.hash();
        self.author_signature.check_validity(&expected_msg, &self.header.author)
    }


    /// TODO: Fill this in.
    fn is_valid(&self) -> bool {
        false
    }
}

impl BlockHeader {
    pub fn new(parent: Option<DoubleSha256Hash>,
               our_inst_addr: InstAddress) -> BlockHeader {
        let parent_hash = match parent {
            None => DoubleSha256Hash::genesis_block_parent_hash(),
            Some(h) => h,
        };
        BlockHeader {
            timestamp: time::get_time().sec,
            parent: parent_hash,
            author: our_inst_addr,
        }
    }

    pub fn hash(&self) -> DoubleSha256Hash {
        /*
         * IMPORTANT: We opt to hash a custom string representation
         * of the block header because we want to be able to reproduce
         * this block header hash in client-side JS. If we depend on rustc
         * serialization, on MsgPack, or on Serde, we will not be able to
         * reproduce this nearly as easily, especially as those libraries
         * change.
         * TODO: Keep this in mind, and continue to add fields of BlockHeader
         * to this hash as they are added during development.
         */
        let to_hash = format!("BLOCKHEADER:{},{},{}",
                              self.timestamp,
                              self.parent,
                              self.author);
        DoubleSha256Hash::hash(&to_hash.as_bytes()[..])
    }
}

impl DocumentSummary {
    fn new(block: &Block, action: Action) -> DocumentSummary {
        match action {
            Action::Certify(doc_id, doc_type, student_id) => {
                DocumentSummary {
                    doc_id: doc_id,
                    doc_type: doc_type,
                    student_id: student_id,
                    cert_timestamp: Some(block.header.timestamp),
                    rev_timestamp: None
                }
            },
            Action::AddPeer(_, _, _) => {
                panic!("Cannot create DocumentSummary from AddPeer;
                        action; calling code needs to prevent this.")
            }
        }
    }
}

impl ser::Serialize for DocumentType {
    fn serialize<S: ser::Serializer>(&self, s: &mut S)
        -> Result<(), S::Error> {
        s.visit_str(&format!("{:?}", self)[..])
    }
}

impl de::Deserialize for DocumentType {
    fn deserialize<D: de::Deserializer>(d: &mut D)
            -> Result<DocumentType, D::Error> {

        struct DocumentTypeVisitor;

        impl de::Visitor for DocumentTypeVisitor {
            type Value = DocumentType;

            fn visit_str<E: de::Error>(&mut self, value: &str)
                    -> Result<DocumentType, E> {
                match value {
                    "Diploma" => Ok(DocumentType::Diploma),
                    "Transcript" => Ok(DocumentType::Transcript),
                    _ => Err(de::Error::syntax(&format!(
                                "The visited string {} could not be deserialized \
                                into a DocumentType.", value)[..]))
                }
            }
        }

        d.visit_str(DocumentTypeVisitor)
    }
}

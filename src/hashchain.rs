use hash::DoubleSha256Hash;
use address::InstAddress;
use serde::{ser, de};
use std::collections::{BTreeSet, BTreeMap, HashMap, HashSet};
use std::collections::vec_deque::VecDeque;
use time;
use std::sync::{Arc, RwLock};
use network::{NetNodeTable, SignatureRequest, BlocksRequest, BlockManifest};
use signature::RecovSignature;
use secp256k1::key::SecretKey;
use serde::ser::Serialize;
use serde_json::Value;
use std::cmp;

pub type DocumentId = DoubleSha256Hash;

#[derive(Serialize, Deserialize)]
pub struct Hashchain {
    chain: HashMap<DoubleSha256Hash, ChainNode>,
    author: InstAddress,
    head_node: Option<DoubleSha256Hash>,
    tail_node: Option<DoubleSha256Hash>,
    merkle_tree: MerkleTree,
    processing_block: Option<Block>,
    queued_blocks: VecDeque<Block>,
    sigreqs_pending_sync: HashMap<DoubleSha256Hash, SignatureRequest>,
}

#[derive(Serialize, Deserialize)]
pub struct MerkleTree {
    tree: BTreeMap<DocumentId, MerkleNode>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MerkleNode {
    document_id: DocumentId,
    certified_ts: i64,
    certified_block_height: usize,
    revoked_ts: Option<i64>,
    revoked_block_height: Option<usize>,
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
    author_signature: RecovSignature,
    signoff_peers: BTreeSet<InstAddress>,
    signoff_signatures: HashMap<InstAddress, RecovSignature>,
    node_locations: BTreeMap<InstAddress, String>,
}

#[derive(Serialize, Deserialize, RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct BlockHeader {
    timestamp: i64,
    pub parent: DoubleSha256Hash,
    pub author: InstAddress,
    merkle_root: DoubleSha256Hash,
    signoff_peers_hash: DoubleSha256Hash,
    node_locations_hash: DoubleSha256Hash,
}

#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub enum DocumentType {
    Diploma,
    Transcript
}

#[derive(Serialize, Deserialize, RustcEncodable, RustcDecodable, Clone, Debug)]
pub enum Action {
    AddPeer(InstAddress, String, u16),
    RemovePeer(InstAddress),
    Certify(DocumentId, DocumentType, String),
    Revoke(DocumentId),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DocumentSummary {
    doc_id: DocumentId,
    doc_type: DocumentType,
    student_id: String,
    cert_timestamp: i64,
    rev_timestamp: Option<i64>,
}

#[derive(Debug)]
pub enum AppendErr {
    MissingBlocksSince(DoubleSha256Hash),
    BlockAlreadyInChain,
    BlockParentAlreadyClaimed,
    ChainStateCorrupted,
    NoSignoffPeersListed,
    AuthorSignatureInvalid,
    MissingPeerSignature,
    InvalidPeerSignature,
    UnexpectedSignoffPeers,
    UnexpectedSignoffPeersHash,
    InvalidActionFound(MerkleTreeErr),
    UnexpectedMerkleRootHash,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RequireAllPeerSigs {
    Yes,
    No
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DocumentStatusProof {
    contents: Value,
    most_recent_block_header: BlockHeader,
    peer_signatures: HashMap<InstAddress, RecovSignature>,
    author_signature: RecovSignature,
    node_locations: BTreeMap<InstAddress, String>,
    merkle_node: MerkleNode,
    merkle_proof: MerkleProof,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MerkleProof {
    branches: Vec<MerkleProofBranch>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MerkleProofBranch {
    position: String,
    hash: DoubleSha256Hash,
}

impl Hashchain {
    pub fn new(author: InstAddress) -> Hashchain {
        Hashchain {
            chain: HashMap::new(),
            author: author,
            head_node: None,
            tail_node: None,
            merkle_tree: MerkleTree::new(),
            processing_block: None,
            queued_blocks: VecDeque::new(),
            sigreqs_pending_sync: HashMap::new(),
        }
    }

    pub fn get_document_status_proof(&self, docid: DocumentId, doc_contents: Value)
            -> DocumentStatusProof {
        match self.tail_node {
            None => panic!("TODO: Handle this rare situation gracefully."),
            Some(hash) => {
                let ref block = self.chain.get(&hash).unwrap().block;
                DocumentStatusProof {
                    contents: doc_contents,
                    most_recent_block_header: block.header.clone(),
                    peer_signatures: block.signoff_signatures.clone(),
                    author_signature: block.author_signature.clone(),
                    node_locations: block.node_locations.clone(),
                    merkle_node: self.merkle_tree.get_node(docid),
                    merkle_proof: self.merkle_tree.merkle_proof(docid),
                }
            }
        }
    }

    /// This method retrieves a block by its block height, because actions
    /// are tied to the block height rather than their block hash. This is because
    /// when a block is authored, its header is based in part on its merkle root; if
    /// we require nodes (actions) in the merkle tree to refer to the hash of the
    /// block currently being constructed, we get a circular dependency. We break that
    /// by using block height in the action; this is acceptable because our hashchains
    /// are not allowed to branch.
    /// TODO: This method is inefficient (O(n) in the number of blocks); eventually
    /// index blocks by height for O(1) lookup.
    pub fn get_block(&self, block_height: usize) -> Option<Block> {
        if block_height == 0 || block_height > self.chain.len()
                || self.head_node.is_none() {
            return None
        } else {
            let mut idx = 1;
            let mut lookup_hash = self.head_node.unwrap();
            while idx < block_height {
                match self.chain.get(&lookup_hash) {
                    None => return None,
                    Some(ref chain_node) => {
                        match chain_node.next_block {
                            None => return None,
                            Some(ref hash) => {
                                lookup_hash = hash.clone();
                                idx += 1;
                            }
                        }
                    }
                }
            }
            return Some(self.chain.get(&lookup_hash).unwrap().block.clone());
        }
    }

    /// This is the authoritative method for checking whether a given
    /// block can be appended to a hashchain instance, be it an institution's
    /// own hashchain or a replica chain belonging to a peer.
    /// NOTE: This method requires a mutable borrow on self but does not
    /// actually change its state in a way that persists after returning;
    /// the explanation is provided in the documentation for
    /// MerkleTree::compute_root_with_actions.
    pub fn is_block_eligible_for_append(
            &mut self, block: &Block,
            require_peer_sigs: RequireAllPeerSigs) -> Result<(), AppendErr> {

        // The author of the block must match the author of this chain.
        if block.header.author != self.author {
            panic!("Attempted to add block authored by {} to chain authored by \
                    {}; the caller is doing something wrong.",
                    block.header.author, self.author);
        }

        // The author's signature must be valid.
        if block.author_signature.check_validity(
                        &block.header.hash(), &block.header.author).is_err() {
            return Err(AppendErr::AuthorSignatureInvalid);
        }

        // Blocks must have at least one signoff peer.
        if block.signoff_peers.len() == 0 {
            return Err(AppendErr::NoSignoffPeersListed);
        }

        // Is this block already present in the chain?
        if self.chain.contains_key(&block.header.hash()) {
            return Err(AppendErr::BlockAlreadyInChain)
        }

        if block.header.parent == DoubleSha256Hash::genesis_block_parent_hash() {
            // If this is the genesis block, ensure our replica state
            // reflects that expectation.
            if self.head_node != None
                    || self.tail_node != None
                    || self.chain.len() > 0 {
                return Err(AppendErr::ChainStateCorrupted)
            }
        } else {
            // Otherwise, if this is not the genesis block, determine
            // if we are missing blocks or if the parent has already been
            // claimed.
            match self.tail_node {
                None => {
                    // If we have nothing in the replica chain and the peer
                    // is sending us a non-genesis block, we have to sync
                    // our replica up starting from the genesis hash (000000...).
                    return Err(AppendErr::MissingBlocksSince(
                            DoubleSha256Hash::genesis_block_parent_hash()))
                },
                Some(tail_hash) => {
                    match self.chain.get(&block.header.parent) {
                        None => {
                            // If we don't have the block's parent, we must
                            // be missing blocks issued since our recorded tail.
                            return Err(AppendErr::MissingBlocksSince(tail_hash));
                        },
                        Some(parent_block_node) => {
                            // Is the parent already claimed?
                            if parent_block_node.next_block.is_some() {
                                return Err(AppendErr::BlockParentAlreadyClaimed);
                            }
                            // If the parent is not already claimed, it should
                            // be the tail of our append-only hashchain. Do a
                            // sanity check to be sure.
                            if tail_hash != parent_block_node.block.header.hash() {
                                return Err(AppendErr::ChainStateCorrupted)
                            }
                        }
                    }
                }
            };
        }

        // The signoff peers in the block must match those that we expect
        // based on what we know of the replica. IT IS IMPORTANT that this
        // check come after the check for missing blocks; if there are missing
        // blocks, this check will typically fail, and if we return this error
        // instead of a missing blocks error, it will not allow the caller
        // to retrieve the blocks.
        let computed_signoff_peers = self.get_signoff_peers(&block.actions);
        if block.signoff_peers != computed_signoff_peers {
            return Err(AppendErr::UnexpectedSignoffPeers);
        }
        if block.header.signoff_peers_hash !=
                BlockHeader::signoff_peers_to_hash(&computed_signoff_peers) {
            return Err(AppendErr::UnexpectedSignoffPeersHash);
        }

        // Ensure that the block header's merkle root matches what we expect
        // as well; for the same reason as given above for signoff peer
        // verification, it's important to do this after
        // checking for missing blocks.
        let computed_merkle_root =
                match self.merkle_tree.compute_root_with_actions(
            block.header.timestamp, self.chain.len() + 1, &block.actions) {
            Ok(hash) => hash,
            Err(merkle_err) =>
                return Err(AppendErr::InvalidActionFound(merkle_err))
        };
        if block.header.merkle_root != computed_merkle_root {
            return Err(AppendErr::UnexpectedMerkleRootHash);
        }

        // When a signature request is received from a peer for its block,
        // we don't require all peer signatures to be present, hence the option.
        // All other use cases will generally want to require that all
        // peer signatures be present.
        if require_peer_sigs == RequireAllPeerSigs::Yes {
            for peer_addr in &block.signoff_peers {
                match block.signoff_signatures.get(&peer_addr) {
                    None => return Err(AppendErr::MissingPeerSignature),
                    Some(peer_sig) => {
                        if peer_sig.check_validity(
                            &block.header.hash(), &peer_addr).is_err() {
                            return Err(AppendErr::InvalidPeerSignature);
                        }
                    }
                };
            }
        }

        Ok(())
    }

    pub fn append_block(&mut self, block: Block) {

        // Make absolutely sure that this block is eligible
        // to be appended to the chain.
        match self.is_block_eligible_for_append(&block,
                                                RequireAllPeerSigs::Yes) {
            Ok(_) => {
                let block_header_hash = block.header.hash();
                self.chain.insert(block_header_hash.clone(),
                    ChainNode::new(block.clone()));
                self.tail_node = Some(block_header_hash.clone());
                if self.head_node == None {
                    // If this is the first block, adjust the chain head.
                    self.head_node = Some(block_header_hash.clone());
                } else {
                    // Otherwise, get the parent and set its next_block;
                    // we can unwrap here because we know parent exists.
                    let ref mut parent = self.chain.get_mut(
                        &block.header.parent).unwrap();
                    parent.next_block = Some(block_header_hash.clone());
                }
                // Commit block actions to internal merkle tree.
                self.merkle_tree.commit_block(block, self.chain.len());
                info!("Block successfully appended to chain.");
            },
            Err(err) => {
                panic!("Failed to append block; this should \
                        never happen; reason is: {:?}", err);
            }
        }
    }

    /// Queues a new block for signing, but importantly, signature
    /// requests are not sent by this method. When the FSM transitions
    /// to process the queue, signatures will be sent once all prior
    /// queued blocks have been signed and finalized.
    pub fn queue_new_block(&mut self,
                           node_table: Arc<RwLock<NetNodeTable>>,
                           actions: Vec<Action>,
                           our_secret_key: &SecretKey) {
        let ref node_table = *node_table.read().unwrap();
        let our_inst_addr = node_table.get_our_inst_addr();
        let signoff_peers = self.get_signoff_peers(&actions);
        let node_locations = node_table.get_node_locations(&signoff_peers);
        let timestamp = time::get_time().sec;
        // TODO: Handle this rather than unwrapping.
        let merkle_root = match self.merkle_tree.compute_root_with_actions(
            timestamp, self.chain.len() + 1, &actions) {
            Ok(hash) => hash,
            Err(err) => panic!("Unable to queue block; merkle err: {:?}", err)
        };
        self.queued_blocks.push_back(
            Block::new(self.tail_node,
                       timestamp,
                       our_inst_addr,
                       merkle_root,
                       signoff_peers,
                       actions,
                       node_locations,
                       &our_secret_key));
    }

    /// Determines the peers whose signatures are required for a set of block
    /// actions to be added to the hashchain. This includes existing peers and peers
    /// being added in 'actions', and excludes peers being removed in 'actions'.
    /// TODO: This method is inefficient as it effectively replays history;
    /// eventually write this in a more performant manner.
    pub fn get_signoff_peers(&self,
                             actions: &Vec<Action>) -> BTreeSet<InstAddress> {

        // Replay history to determine who our existing peers are,
        // as they are required to sign off.
        // We iterate through the chain from front to back; we
        // cannot use HashMap's iter as its ordering is unpredictable.
        let mut peers = BTreeSet::new();
        let mut lookup_hash = self.head_node;
        while lookup_hash.is_some() {
            match self.chain.get(&lookup_hash.unwrap()) {
                None => break,
                Some(ref chain_node) => {
                    for action in chain_node.block.actions.iter() {
                        match *action {
                            Action::AddPeer(inst_addr, _, _) => {
                                peers.insert(inst_addr);
                            },
                            Action::RemovePeer(inst_addr) => {
                                peers.remove(&inst_addr);
                            },
                            Action::Certify(_, _, _)
                            | Action::Revoke(_) => (),
                        }
                    }
                    lookup_hash = chain_node.next_block;
                }
            }
        }

        // Additionally, play the provided actions atop history.
        // Remember that peers removed in a block are not
        // required to sign off on that block, and thus are excluded
        // here as well.
        for action in actions.iter() {
            match *action {
                Action::AddPeer(inst_addr, _, _) => {
                    peers.insert(inst_addr);
                },
                Action::RemovePeer(inst_addr) => {
                    peers.remove(&inst_addr);
                },
                Action::Certify(_, _, _)
                | Action::Revoke(_) => (),
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

        if self.processing_block.is_none() {
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
            for peer_addr in &block_to_process.signoff_peers {
                let sigreq = SignatureRequest::new(peer_addr.clone(),
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
        } else {
            let proc_block = self.processing_block.as_ref().unwrap().clone();
            match self.is_block_eligible_for_append(
                    &proc_block,
                    RequireAllPeerSigs::Yes) {
                Ok(_) => {
                    info!("HCHAIN: Block is now eligible for append; \
                           adding to chain and broadcasting.");
                    let block = self.processing_block.as_ref().unwrap().clone();
                    self.append_block(block.clone());
                    self.processing_block = None;

                    // Broadcast the signed block to all signoff peers so
                    // they can include it in their replicas.
                    for peer_addr in &block.signoff_peers {
                        let mf = BlockManifest::new(block.clone());
                        match node_table.write().unwrap()
                                .send_block_manifest(peer_addr, mf.clone()) {
                            Ok(()) => info!("Block manifest sent to {}", peer_addr),
                            Err(_) => panic!("TODO: Unable to send block manifest \
                                              to peer; a flag/retry interval needs \
                                              to be set. This is not critical \
                                              because next signing will involve \
                                              sync, but should be done anyway.")
                        }
                    }
                    return true;
                },
                Err(err) => {
                    info!("HCHAIN: Block is not yet \
                          eligible for append: {:?}", err);
                    return false;
                }
            };
        }
    }

    /// Use this method to add a signature received from a peer to
    /// the block being processed.
    pub fn submit_processing_block_signature(&mut self,
                                             sig_author: InstAddress,
                                             signature: RecovSignature) {
        // If no block is being processed, don't continue.
        if self.processing_block.is_none() {
            warn!("Ignoring submitted peer signature for block; no \
                   block is being processed right now. It's possible
                   that the block was aborted.");
            return
        }

        // Before attaching the signature to the block,
        // ensure that the signature is valid for the block
        // being processed and the provided author's address.
        let ref mut block = self.processing_block.as_mut().unwrap();
        match signature.check_validity(
                &block.header.hash(),
                &sig_author) {
            Ok(_) => {
                block.signoff_signatures
                        .insert(sig_author, signature);
            }, Err(_) => {
                panic!("When submitting a block signature, the sig was found
                        to be invalid. Understand why this occurred.");
            }
        }
    }

    pub fn handle_blocks_req(&self,
                             blocks_req: BlocksRequest,
                             node_table: Arc<RwLock<NetNodeTable>>) {
        let _ = blocks_req.check_validity(&self.author).is_err();
    }

    pub fn get_certifications(&self,
                optional_student_id: Option<&str>) -> Vec<DocumentSummary> {
        if self.head_node.is_none() { return Vec::new() }
        let mut summaries = HashMap::new();
        let mut lookup_hash = self.head_node;
        // Iterate through the chain from front to back; this is important,
        // because processing revocations depends on the certification
        // being processed beforehand.
        while lookup_hash.is_some() {
            match self.chain.get(&lookup_hash.unwrap()) {
                None => break,
                Some(ref chain_node) => {
                    for action in chain_node.block.actions.iter() {
                        match *action {
                            Action::Certify(docid, _, ref sid) => {
                                if optional_student_id.is_none()
                                    || (optional_student_id.unwrap() == sid) {
                                    summaries.insert(docid,
                                        DocumentSummary::new(&chain_node.block,
                                                             action.clone()));
                                }
                            },
                            Action::Revoke(docid) => {
                                match summaries.get_mut(&docid) {
                                    // This can legitimately yield None, i.e.,
                                    // if optional_student_id is provided and
                                    // this Revocation is for a document
                                    // issued to a different student.
                                    None => (),
                                    Some(ref mut summary) => {
                                        if optional_student_id.is_none()
                                            || (optional_student_id.unwrap()
                                                == summary.student_id) {
                                            summary.rev_timestamp = Some(
                                                chain_node.block.header.timestamp);
                                        }
                                    }
                                }
                            },
                            Action::RemovePeer(_)
                            | Action::AddPeer(_, _, _) => {
                                continue;
                            }
                        }
                    }
                    lookup_hash = chain_node.next_block;
                }
            }
        }

        let mut s_vec : Vec<DocumentSummary> = summaries.iter().map(|(_, s)| s.clone()).collect();
        s_vec.sort();
        s_vec
    }
}

#[derive(Debug)]
pub enum MerkleTreeErr {
    DuplicateCertification,
    RevocationOfNonexistentCertification,
    DuplicateRevocation
}

impl MerkleProof {
    fn new() -> MerkleProof {
        MerkleProof {
            branches: Vec::new()
        }
    }

    fn add_left_branch(&mut self, hash: DoubleSha256Hash) {
        self.branches.push(MerkleProofBranch {
            position: String::from("L"),
            hash: hash
        });
    }

    fn add_right_branch(&mut self, hash: DoubleSha256Hash) {
        self.branches.push(MerkleProofBranch {
            position: String::from("R"),
            hash: hash
        });
    }
}

impl MerkleTree {
    fn new() -> MerkleTree {
        MerkleTree {
            tree: BTreeMap::new(),
        }
    }

    fn get_node(&self, docid: DocumentId) -> MerkleNode {
        self.tree.get(&docid).unwrap().clone()
    }

    /// Computes the Merkle root of the tree that would result
    /// after committing the provided block actions. Although this requires
    /// a mutable borrow on this tree, changes made during this
    /// function are reverted before returning. To permanently
    /// apply a block to the tree, you must use commit_block below.
    fn compute_root_with_actions(&mut self,
                               block_ts: i64,
                               block_height: usize,
                               actions: &Vec<Action>)
        -> Result<DoubleSha256Hash, MerkleTreeErr> {
        let mut to_delete = HashSet::new();
        let mut to_revert = HashSet::new();
        for action in actions.iter() {
            match *action {
                Action::AddPeer(_, _, _)
                | Action::RemovePeer(_) => continue,
                Action::Certify(docid, _, _) => {
                    if self.tree.contains_key(&docid) {
                        return Err(MerkleTreeErr::DuplicateCertification)
                    }
                    to_delete.insert(docid);
                    self.tree.insert(docid, MerkleNode {
                        document_id: docid,
                        certified_ts: block_ts,
                        certified_block_height: block_height,
                        revoked_ts: None,
                        revoked_block_height: None
                    });
                },
                Action::Revoke(docid) => {
                    match self.tree.get_mut(&docid) {
                        None => return Err(
                            MerkleTreeErr::RevocationOfNonexistentCertification),
                        Some(ref mut m_node) => {
                            if m_node.revoked_ts.is_some()
                                || m_node.revoked_block_height.is_some() {
                                return Err(MerkleTreeErr::DuplicateRevocation)
                            }
                            to_revert.insert(docid);
                            m_node.revoked_ts = Some(block_ts);
                            m_node.revoked_block_height = Some(block_height);
                        }
                    }
                }
            }
        }

        let root_with_actions = self.merkle_root();

        // Delete and revert our modifications.
        for docid in to_delete.iter() {
            self.tree.remove(docid);
        }
        for docid in to_revert.iter() {
            let m_node = self.tree.get_mut(&docid).unwrap();
            m_node.revoked_ts = None;
            m_node.revoked_block_height = None;
        }

        Ok(root_with_actions)
    }

    fn merkle_root(&self) -> DoubleSha256Hash {
        fn merkle_root(elements: Vec<DoubleSha256Hash>) -> DoubleSha256Hash {
            if elements.len() == 0 {
                return DoubleSha256Hash::blank()
            }
            if elements.len() == 1 {
                return elements[0]
            }
            let mut parent_row = vec![];
            /*
             * This loop has been adapted from the one used by
             * Andrew Poelstra in his rust-bitcoin project;
             * loops ensures odd-length vecs will have last
             * element duplicated, w/o modification of the vec itself.
             */
            for i in 0..((elements.len() + 1) / 2) {
                let a = elements[i*2];
                let b = elements[cmp::min(i*2 + 1, elements.len() - 1)];
                let combined = a.to_string() + &b.to_string();
                parent_row.push(DoubleSha256Hash::hash_string(&combined))
            }
            merkle_root(parent_row)
        }
        merkle_root(self.tree.iter().map(|(_, m_node)| {
            DoubleSha256Hash::hash_string(&m_node.as_string())
        }).collect())
    }

    fn merkle_proof(&self, docid: DocumentId) -> MerkleProof {
        fn merkle_proof(elements: Vec<DoubleSha256Hash>,
                        hash_to_find: DoubleSha256Hash,
                        proof: &mut MerkleProof) {
            if elements.len() < 2 {
                return
            }
            let mut parent_row = vec![];
            /*
             * This loop has been adapted from the one used by
             * Andrew Poelstra in his rust-bitcoin project;
             * loops ensures odd-length vecs will have last
             * element duplicated, w/o modification of the vec itself.
             */
            let mut new_hash_to_find = None;
            debug!("In this row, hash to find is {:?}", hash_to_find);
            for i in 0..((elements.len() + 1) / 2) {
                let a = elements[i*2];
                let b = elements[cmp::min(i*2 + 1, elements.len() - 1)];
                let combined = a.to_string() + &b.to_string();
                debug!("combined: {}", combined);
                let combined_hash = DoubleSha256Hash::hash_string(&combined);
                debug!("combined hash: {}", combined_hash);
                if a == hash_to_find {
                    proof.add_right_branch(b);
                    new_hash_to_find = Some(combined_hash);
                    debug!("Adding *b* to proof.");
                } else if b == hash_to_find {
                    proof.add_left_branch(a);
                    new_hash_to_find = Some(combined_hash);
                    debug!("Adding *a* to proof.");
                }
                parent_row.push(combined_hash);
            }
            if new_hash_to_find.is_none() {
                panic!("Unable to continue proof; no hash to find next.");
            }
            merkle_proof(parent_row, new_hash_to_find.unwrap(), proof)
        }

        // We need to get the hash of the merkle node corresponding to
        // the requested document ID.
        let docid_merkle_node_hash = DoubleSha256Hash::hash_string(
            &self.tree.get(&docid).unwrap().as_string());
        let mut proof = MerkleProof::new();
        merkle_proof(self.tree.iter().map(|(_, m_node)| {
            let st = &m_node.as_string();
            let hash = DoubleSha256Hash::hash_string(
                &m_node.as_string());
            debug!("m_node: {}, hash: {}", st, hash);
            hash
        }).collect(), docid_merkle_node_hash, &mut proof);
        proof
    }

    /// Commits a block to the tree; the changes are permanent and
    /// will be synced to disk when the hashchain is next synced. If
    /// you only want to check what the merkle root will be if a block
    /// is applied, use compute_root_with_block above.
    fn commit_block(&mut self, block: Block, block_height: usize) {
        // Iterate over the block's actions and commit the
        // document-related ones.
        for action in block.actions.iter() {
            match *action {
                Action::AddPeer(_, _, _)
                | Action::RemovePeer(_) => continue,
                Action::Certify(docid, _, _) => {
                    self.tree.insert(docid, MerkleNode {
                        document_id: docid,
                        certified_ts: block.header.timestamp,
                        certified_block_height: block_height,
                        revoked_ts: None,
                        revoked_block_height: None
                    });
                },
                Action::Revoke(docid) => {
                    let ref mut m_node = self.tree.get_mut(&docid).unwrap();
                    m_node.revoked_ts = Some(block.header.timestamp);
                    m_node.revoked_block_height = Some(block_height);
                }
            }
        }
    }
}

impl MerkleNode {
    fn as_string(&self) -> String {
        let certified_str = format!("{}|{:?}|{}",
                self.document_id, self.certified_ts,
                self.certified_block_height);
        if self.revoked_ts.is_some() && self.revoked_block_height.is_some() {
            format!("{}|{:?}|{:?}", certified_str, self.revoked_ts.unwrap(),
                    self.revoked_block_height.unwrap())
        } else {
            certified_str
        }
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
    fn new(parent: Option<DoubleSha256Hash>,
           timestamp: i64,
           our_inst_addr: InstAddress,
           merkle_root: DoubleSha256Hash,
           signoff_peers: BTreeSet<InstAddress>,
           actions: Vec<Action>,
           node_locations: BTreeMap<InstAddress, String>,
           our_secret_key: &SecretKey) -> Block {
        let header = BlockHeader::new(timestamp, parent,
                                      our_inst_addr,
                                      &node_locations,
                                      merkle_root, &signoff_peers);
        let header_hash = header.hash();
        Block {
            header: header,
            actions: actions,
            author_signature: RecovSignature::sign(
                &header_hash, &our_secret_key),
            signoff_peers: signoff_peers,
            signoff_signatures: HashMap::new(),
            node_locations: node_locations,
        }
    }
}

impl BlockHeader {
    pub fn new(timestamp: i64,
               parent: Option<DoubleSha256Hash>,
               our_inst_addr: InstAddress,
               node_locations: &BTreeMap<InstAddress, String>,
               merkle_root: DoubleSha256Hash,
               signoff_peers: &BTreeSet<InstAddress>) -> BlockHeader {
        let parent_hash = match parent {
            None => DoubleSha256Hash::genesis_block_parent_hash(),
            Some(h) => h,
        };

        // Create a string containing each node's address and hostname + port.
        // We use BTreeSet here as well in order to ensure lexicographic
        // iteration.
        let mut node_locs_to_hash = String::from("|");
        for (addr, hostname_port) in node_locations.iter() {
            node_locs_to_hash = node_locs_to_hash
                + &addr.to_base58() + ":" + hostname_port + "|";
        }

        BlockHeader {
            timestamp: timestamp,
            parent: parent_hash,
            author: our_inst_addr,
            merkle_root: merkle_root,
            signoff_peers_hash:
                BlockHeader::signoff_peers_to_hash(&signoff_peers),
            node_locations_hash: DoubleSha256Hash::hash_string(
                &node_locs_to_hash)
        }
    }

    /// Creates a hash of the concatenation of each peer's address;
    /// because we are using BTreeSet, iteration will occur
    /// lexicographically, which is important because we want
    /// client-side JS to be able to easily reconstruct this hash.
    fn signoff_peers_to_hash(signoff_peers: &BTreeSet<InstAddress>)
            -> DoubleSha256Hash {
        let mut signoff_peers_to_hash = String::from("|");
        for peer_addr in signoff_peers.iter() {
            signoff_peers_to_hash = signoff_peers_to_hash
                + &peer_addr.to_base58() + "|";
        }
        DoubleSha256Hash::hash_string(&signoff_peers_to_hash)
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
        let to_hash = format!("BLOCKHEADER:{},{},{},{},{},{}",
                              self.timestamp,
                              self.parent,
                              self.author,
                              self.merkle_root,
                              self.signoff_peers_hash,
                              self.node_locations_hash);
        DoubleSha256Hash::hash_string(&to_hash)
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
                    cert_timestamp: block.header.timestamp,
                    rev_timestamp: None
                }
            },
            Action::Revoke(_) => {
                panic!("TODO: Handle Revoke in DocumentSummary constructor.");
            },
            a @ Action::RemovePeer(_)
            | a @ Action::AddPeer(_, _, _) => {
                panic!("Cannot create DocumentSummary from AddPeer
                        or RemovePeer; calling code needs to \
                        prevent this: {:?}", a)
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

// DocumentSummaries are ordered by cert_timestamp; most
// recent comes before least.
impl Ord for DocumentSummary {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        other.cert_timestamp.cmp(&self.cert_timestamp)
    }
}
impl PartialOrd for DocumentSummary {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(other.cmp(&self))
    }
}
impl PartialEq for DocumentSummary {
    fn eq(&self, other: &Self) -> bool {
        self.cert_timestamp == other.cert_timestamp
    }
}
impl Eq for DocumentSummary {}

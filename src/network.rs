use std::net::{TcpListener, TcpStream};
use std::io;
use std;
use config::CertChainConfig;
use std::thread;
use std::sync::{Arc, RwLock, Mutex};
use std::sync::mpsc::{Sender};
use std::ops::DerefMut;
use std::io::{Write, BufReader, BufWriter};
use rustc_serialize::{Encodable, Decodable, Encoder};
use address::InstAddress;
use secp256k1::key::{SecretKey};
use common::ValidityErr;
use key;
use std::fmt::{Display, Formatter};
use signature::RecovSignature;
use hash::DoubleSha256Hash;
use std::hash::{Hash};
use rand::os::OsRng;
use rand::Rng;
use compress::checksum::adler;
use std::collections::{HashMap, BTreeSet, BTreeMap};
use msgpack;
use hashchain::{Hashchain, Action, Block,
                AppendErr, RequireAllPeerSigs};
use fsm::{FSM, FSMState};
use std::fs::File;
use serde_json;

const MAINNET_MSG_MAGIC: u32 = 0x48FFABCD;

struct Socket {
    tcp_sock: Arc<Mutex<Option<TcpStream>>>,
}

#[derive(RustcEncodable, RustcDecodable, Debug)]
struct NetworkMessage {
    magic: u32,
    payload: NetPayload,
    payload_checksum: u32,
}

#[derive(RustcEncodable, RustcDecodable, Debug)]
pub enum NetPayload {
    IdentReq(IdentityRequest),
    IdentResp(IdentityResponse),
    PeerReq(PeerRequest),
    SigReq(SignatureRequest),
    SigResp(SignatureResponse),
    BlocksReq(BlocksRequest),
    BlockManifest(BlockManifest),
}

#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct IdentityRequest {
    pub nonce: u64,
    pub to_inst_addr: InstAddress,
    pub to_hostname: String,
    pub to_port: u16,
    pub from_inst_addr: InstAddress,
    pub from_hostname: String,
    pub from_port: u16,
    pub from_signature: RecovSignature,
}

#[derive(RustcEncodable, RustcDecodable, Clone, Debug,
         Serialize, Deserialize)]
pub struct SignatureRequest {
    pub nonce: u64,
    pub to_inst_addr: InstAddress,
    pub block: Block,
    pub from_signature: RecovSignature,
}

#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct SignatureResponse {
    pub nonce: u64,
    pub to_inst_addr: InstAddress,
    pub from_inst_addr: InstAddress,
    pub block_header_hash: DoubleSha256Hash,
    pub block_header_hash_signature: RecovSignature,
    pub from_signature: RecovSignature,
}

#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct BlocksRequest {
    pub to_inst_addr: InstAddress,
    pub from_inst_addr: InstAddress,
    pub after_block_hash: DoubleSha256Hash,
    pub from_signature: RecovSignature,
}

#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct BlockManifest {
    pub block: Block
}

#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct PeerRequest {
    pub nonce: u64,
    pub to_inst_addr: InstAddress,
    pub from_inst_addr: InstAddress,
    pub from_signature: RecovSignature,
}

#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct IdentityResponse {
    pub nonce: u64,
    pub from_inst_addr: InstAddress,
    pub from_signature: RecovSignature,
}

#[derive(Debug, PartialEq)]
enum ConnectionState {
    NotConnected,
    Connected,
}

#[derive(Debug, PartialEq)]
enum IdentityState {
    NotConfirmed,
    Confirmed
}

#[derive(RustcEncodable, RustcDecodable, Serialize,
         Deserialize, Clone, Debug, PartialEq)]
pub enum PeeringApproval {
    NotApproved,
    AwaitingTheirApproval,
    AwaitingOurApproval,
    Approved,
}

pub struct NetNodeTable {
    node_map: Arc<RwLock<HashMap<InstAddress, NetNode>>>,
    our_inst_addr: InstAddress,
    our_hostname: String,
    our_port: u16,
    replica_dir: String,
}

struct NetNode {
    inst_addr: InstAddress,
    hostname: String,
    port: u16,
    socket: Socket,
    conn_state: ConnectionState,
    ident_state: IdentityState,
    our_peering_approval: PeeringApproval,
    identreq: Option<IdentityRequest>,
    identresp: Option<IdentityResponse>,
    awaiting_sigreq: Option<SignatureRequest>,
    hc_replica: Option<Arc<RwLock<Hashchain>>>,
}

#[derive(Serialize, Deserialize)]
pub struct OnDiskNetNode {
    pub inst_addr: String,
    pub hostname: String,
    pub port: u16,
    pub our_peering_approval: PeeringApproval,
}

impl Encodable for NetNodeTable {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_struct("NetNodeTable", 1, |s| {
            try!(s.emit_struct_field("node_map", 0, |s| {
                try!(s.emit_map(1, |s| {
                    let ref node_map: HashMap<InstAddress, NetNode>
                        = *self.node_map.read().unwrap();
                    let mut idx = 0;
                    for (key, val) in node_map.iter() {
                        try!(s.emit_map_elt_key(idx, |s|
                            key.to_string().encode(s)));
                        try!(s.emit_map_elt_val(idx, |s|
                            val.encode(s)));
                        idx += 1;
                    }
                    Ok(())
                }));
                Ok(())
            }));
            try!(s.emit_struct_field("our_inst_addr", 1,
                    |s| self.our_inst_addr.to_string().encode(s)));
            try!(s.emit_struct_field("our_hostname", 2,
                    |s| self.our_hostname.encode(s)));
            try!(s.emit_struct_field("our_port", 3,
                    |s| self.our_port.encode(s)));
            Ok(())
        })
    }
}

impl Encodable for NetNode {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_struct("NetNode", 1, |s| {
            try!(s.emit_struct_field("inst_addr", 0,
                    |s| self.inst_addr.to_string().encode(s)));
            try!(s.emit_struct_field("hostname", 1,
                    |s| self.hostname.encode(s)));
            try!(s.emit_struct_field("port", 2,
                    |s| self.port.encode(s)));
            try!(s.emit_struct_field("conn_state", 3,
                    |s| format!("{:?}", self.conn_state).encode(s)));
            try!(s.emit_struct_field("ident_state", 4,
                    |s| format!("{:?}", self.ident_state).encode(s)));
            try!(s.emit_struct_field("our_peering_approval", 5,
                    |s| format!("{:?}", self.our_peering_approval).encode(s)));
            Ok(())
        })
    }
}

impl NetNodeTable {

    pub fn new(config: &CertChainConfig) -> NetNodeTable {
        let inst_pubkey = key::compressed_public_key_from_string(
                &config.compressed_public_key).unwrap();
        let inst_addr = InstAddress::from_pubkey(&inst_pubkey).unwrap();
        info!("This node identifies itself as {}.", inst_addr);
        NetNodeTable {
            node_map: Arc::new(RwLock::new(HashMap::new())),
            our_inst_addr: inst_addr,
            our_hostname: String::from(&config.hostname[..]),
            our_port: config.port,
            replica_dir: String::from(&config.path_to("replicas")[..]),
        }
    }

    pub fn get_our_inst_addr(&self) -> InstAddress {
        self.our_inst_addr
    }

    /// Gets the node locations of the InstAddresses passed in the argument
    /// set, as well as our own location.
    pub fn get_node_locations(&self, signoff_peers: &BTreeSet<InstAddress>)
            -> BTreeMap<InstAddress, String> {
        let mut map = BTreeMap::new();
        map.insert(self.our_inst_addr.clone(),
            format!("{}:{}", self.our_hostname, self.our_port));
        for peer_addr in signoff_peers.iter() {
            let ref node_map = *self.node_map.read().unwrap();
            let ref node = node_map.get(&peer_addr).unwrap();
            map.insert(peer_addr.clone(), format!("{}:{}", node.hostname, node.port));
        }
        map
    }

    /// Creates a condensed representation of this NetNodeTable suitable
    /// for storage on disk, without transient fields included.
    pub fn to_disk(&self) -> Vec<OnDiskNetNode> {
        let ref node_map = *self.node_map.read().unwrap();
        let mut nodes = Vec::new();
        for (_, node) in node_map.iter() {
            nodes.push(node.to_disk());
        }
        nodes
    }

    /// Registers an institution as a node based on their institutional address.
    pub fn register(&mut self,
                    node_addr: InstAddress,
                    hostname: &String,
                    port: u16,
                    our_peering_approval: PeeringApproval) {
        let mut node_map = self.node_map.write().unwrap();
        match node_map.get(&node_addr) {
            Some(_) => info!("Already registered {}; \
                        ignorning call to re-register it.", node_addr),
            None => {
                let node = NetNode::new(node_addr,
                                        hostname, port, our_peering_approval);
                node_map.insert(node_addr, node);
            }
        }
    }

    /// Removes a node from the node table.
    pub fn remove_node(&mut self,
                    node_addr: InstAddress) -> std::io::Result<()> {
        let mut node_map = self.node_map.write().unwrap();
        match node_map.get(&node_addr) {
            Some(node) => {
                if node.our_peering_approval != PeeringApproval::NotApproved {
                    // Technically speaking, we really only care if the node
                    // is considered a peer according to our hashchain; approval
                    // is only used as a proxy for that here temporarily.
                    // TODO: Eventually convert this to a check against the
                    // hashchain, rather then looking at the approval status
                    // (will need to issue RemovePeer action when removing a peer).
                    return Err(io::Error::new(io::ErrorKind::Other,
                        format!("You must end peering with this \
                                node before you can remove it.")))
                }
            },
            None => {
                info!("Ignoring call to remove node {}; \
                        it does not exist.", node_addr);
                return Ok(())
            }
        };
        node_map.remove(&node_addr);
        Ok(())
    }

    /// Connects to a node, or reconnects if already connected.
    /// If a secret key is provided, we will ask
    /// that node to confirm their identity.
    pub fn connect(&mut self, node_addr: InstAddress,
                   secret_key: Option<&SecretKey>) -> std::io::Result<()> {
        match self.node_map.write().unwrap().get_mut(&node_addr) {
            Some(mut node) => {
                // Note that we are forcing a new connection to
                // be made on each call to this method. This is important
                // for those times when a socket may be old and the caller
                // wishes to send a message down a fresh connection to
                // ensure receipt.
                node.socket = Socket::new();
                node.conn_state = ConnectionState::NotConnected;
                if let Err(_) = node.connect() {
                    return Err(io::Error::new(io::ErrorKind::NotConnected,
                        format!("Node {} is not available, can't connect.",
                        node_addr)));
                }
            },
            None => return Err(io::Error::new(io::ErrorKind::Other,
                    format!("Node {} is not registered, can't connect.",
                    node_addr))),
        };

        // If secret key is provided, ask node to confirm their identity.
        if let Some(ref sec_key) = secret_key {
            if let Err(_) = self.send_identreq(node_addr, sec_key) {
                return Err(io::Error::new(io::ErrorKind::Other,
                    format!("Unable to send identreq to node {}.",
                    node_addr)));
            }
        }
        Ok(())
    }

    fn send_identreq(&mut self, node_addr: InstAddress,
            our_secret_key: &SecretKey) -> std::io::Result<()> {
        let mut node_map = self.node_map.write().unwrap();
        match node_map.get_mut(&node_addr) {
            Some(node) => {
                let identreq = IdentityRequest::new(&node,
                        self.our_inst_addr,
                        &self.our_hostname[..],
                        self.our_port,
                        &our_secret_key);
                match node.send(NetPayload::IdentReq(identreq.clone())) {
                    Ok(_) => {
                        node.identreq = Some(identreq);
                        Ok(())
                    },
                    Err(err) => Err(err)
                }
            },
            None => Err(io::Error::new(io::ErrorKind::Other,
                    format!("Node {} is not registered, can't request identity.",
                    node_addr))),
        }
    }

    pub fn handle_identreq(&mut self, identreq: IdentityRequest,
            our_secret_key: &SecretKey) -> std::io::Result<()> {
        // Determine if the contents of this request are valid.
        if let Err(err) = identreq.check_validity(&self.our_inst_addr,
                &self.our_hostname, &self.our_port) {
            panic!("TODO: Log invalid ident req: {:?}", err)
        }

        // Ensure the node is registered.
        self.register(identreq.from_inst_addr,
                &identreq.from_hostname, identreq.from_port,
                PeeringApproval::NotApproved);

        // If we haven't already, connect and request the node's identity.
        // The node could have disconnected,
        // and if we send the response down the old socket, it will never
        // receive it.
        // TODO: If an error occurs while connecting, queue our IdentResp
        // in the FSM for later sending.
        if self.node_map.read().unwrap().get(&identreq.from_inst_addr)
                .unwrap().identreq.is_none() {
            let _ = self.connect(identreq.from_inst_addr, Some(our_secret_key));
        }

        // Get the node (we can unwrap due to registration call above).
        let mut node_map = self.node_map.write().unwrap();
        let mut node = node_map.get_mut(&identreq.from_inst_addr).unwrap();

        // Create a response and send to the node.
        let identresp = IdentityResponse::new(self.our_inst_addr,
                identreq.nonce, &our_secret_key);
        node.send(NetPayload::IdentResp(identresp))
    }

    pub fn process_identresp(&mut self, identresp: IdentityResponse)
            -> std::io::Result<()> {
        // First, ensure that we actually have a node matching that
        // of the responding institution.
        let mut node_map = self.node_map.write().unwrap();
        let mut node = match node_map.get_mut(&identresp.from_inst_addr) {
            Some(p) => p,
            None => {
                warn!("Ignoring identresp from {}; the responding node \
                       is not registered in our node table.",
                       &identresp.from_inst_addr);
                return Ok(())
            }
        };

        // Next, ensure that we sent out an identity request for this node.
        let identreq = match node.identreq {
            Some(ref req) => req,
            None => {
                warn!("Ignoring identresp from {}; we never \
                       sent out an identreq for this institution.",
                       node.inst_addr);
                return Ok(())
            }
        };

        // Third, check the validity of the response's nonce and signature.
        if let Err(err) = identresp.check_validity(identreq) {
            info!("Identreq: {:?}", identreq);
            info!("Invalid identresp: {:?}", identresp);
            panic!("TODO: Log invalid identresp: {:?}", err)
        }

        // Now that all checks passed, elevate the node's identity status
        // to confirmed.
        node.ident_state = IdentityState::Confirmed;
        node.identresp = Some(identresp);
        info!("Node {} has confirmed their identity to us.", node.inst_addr);
        Ok(())
    }

    pub fn request_peer(&mut self, node_addr: InstAddress,
            our_secret_key: &SecretKey) -> std::io::Result<()> {

        // First, ensure that the provided address maps to a node
        // whose identity has been confirmed.
        if !self.is_confirmed_node(&node_addr) {
            return Err(io::Error::new(io::ErrorKind::Other,
                format!("Ignoring peer request for node {}; their \
                         identity has not been confirmed.", &node_addr)));
        }

        // Second, get the node (we can unwrap due to above check).
        let mut node_map = self.node_map.write().unwrap();
        let mut node = node_map.get_mut(&node_addr).unwrap();

        // Third, create a request and send to the node.
        let peerreq = PeerRequest::new(node_addr,
            self.our_inst_addr, &our_secret_key);
        match node.send(NetPayload::PeerReq(peerreq)) {
            Ok(()) => {
                // If request was sent successfully,
                // update peering state accordingly.
                node.our_peering_approval = PeeringApproval::AwaitingTheirApproval;
                Ok(())
            },
            Err(err) => Err(err)
        }
    }

    pub fn send_sigreq(&mut self, sigreq: SignatureRequest)
            -> std::io::Result<()> {

        // First, ensure that the provided address maps to a node
        // whose identity has been confirmed.
        if !self.is_confirmed_node(&sigreq.to_inst_addr) {
            return Err(io::Error::new(io::ErrorKind::Other,
                format!("Will not send sigreq to node {}; their \
                         identity has not been confirmed.",
                         &sigreq.to_inst_addr)));
        }

        // Second, get the node (we can unwrap due to above check).
        let mut node_map = self.node_map.write().unwrap();
        let mut node = node_map.get_mut(&sigreq.to_inst_addr).unwrap();

        // Third, create a request and send to the node. We store the
        // sigreq on the node for later reference upon receipt of the
        // signature response. Note that we don't care about overwrites here;
        // only one signature request is ever valid for a given node due
        // to the fact that we only process (issue signature requests)
        // for one block at a time.
        node.awaiting_sigreq = Some(sigreq.clone());
        node.send(NetPayload::SigReq(sigreq))
    }

    pub fn handle_sigreq(&mut self,
                         sigreq: SignatureRequest,
                         fsm: Arc<RwLock<FSM>>,
                         our_secret_key: &SecretKey)
            -> std::io::Result<()> {

        // First, determine if the contents of this request are valid.
        // IMPORTANT: This does NOT validate the block within the request;
        // it only validates the request itself.
        if let Err(_) = sigreq.check_validity(&self.our_inst_addr) {
            return Err(io::Error::new(io::ErrorKind::Other,
                format!("Received invalid sigreq; ignoring.")));
        }

        // Ensure that we have confirmed the authoring node's
        // identity.
        if !self.is_confirmed_node(&sigreq.block.header.author) {
            return Err(io::Error::new(io::ErrorKind::Other,
                format!("Ignoring sigreq from {}; their identity
                         has not been confirmed.",
                         &sigreq.block.header.author)));
        }

        // Get the node (we can unwrap due to above check).
        let mut node_map = self.node_map.write().unwrap();
        let mut node = node_map.get_mut(&sigreq.block.header.author).unwrap();

        // Ensure that peering has been approved with the authoring
        // institution.
        match node.our_peering_approval {
            PeeringApproval::Approved => (),
            PeeringApproval::AwaitingTheirApproval => {
                /*
                 * If we receive a sigreq from a peer who we requested
                 * to peer with (i.e., we are awaiting their approval),
                 * we know that they now consider us to be their peer.
                 * Therefore, we upgrade our approval to Approved,
                 * and we queue a new block in our own chain to add them
                 * as our peer.
                 */
                info!("Received sigreq from node that we requested to peer \
                       with; upgrading to Approved and adding them to our \
                       own chain.");
                node.our_peering_approval = PeeringApproval::Approved;
                let ref mut fsm = *fsm.write().unwrap();
                fsm.push_state(FSMState::SyncNodeTableToDisk);

                // Finally, have the FSM queue a new block containing the action
                // and sync the queued block to disk.
                let action = Action::AddPeer(node.inst_addr,
                                             node.hostname.clone(), node.port);
                fsm.push_state(FSMState::QueueNewBlock(vec![action]));
                fsm.push_state(FSMState::SyncHashchainToDisk);
            },
            PeeringApproval::AwaitingOurApproval
                | PeeringApproval::NotApproved => {
                return Err(io::Error::new(io::ErrorKind::Other,
                    format!("Ignoring sigreq from {}; we have not approved
                             a peering relationship with them.",
                             &sigreq.block.header.author)));
            }
        }

        // If the block is eligible to be appended to our replica of
        // the peer's hashchain, issue a signature for it.
        let ref hc_replica = node.lazy_load_replica(&self.replica_dir);
        match hc_replica.write().unwrap()
                .is_block_eligible_for_append(&sigreq.block,
                                              RequireAllPeerSigs::No) {
            Ok(_) => {
                info!("Signing block {} as requested by {} and sending over \
                      network.", &sigreq.block.header.hash(), node.inst_addr);
                let sigresp = SignatureResponse::new(
                    sigreq.nonce, node.inst_addr, self.our_inst_addr,
                    sigreq.block.header.hash(), &our_secret_key);
                return node.send(NetPayload::SigResp(sigresp))
            },
            Err(e @ AppendErr::AuthorSignatureInvalid)
            | Err(e @ AppendErr::NoSignoffPeersListed)
            | Err(e @ AppendErr::MissingPeerSignature)
            | Err(e @ AppendErr::InvalidPeerSignature)
            | Err(e @ AppendErr::UnexpectedSignoffPeers)
            | Err(e @ AppendErr::UnexpectedSignoffPeersHash)
            | Err(e @ AppendErr::InvalidActionFound(_))
            | Err(e @ AppendErr::UnexpectedMerkleRootHash) => {
                info!("Peer {} sent us a sigreq for a block that \
                      we are ignoring due to: {:?}", node.inst_addr, e);
                return Ok(())
            },
            Err(AppendErr::BlockAlreadyInChain) =>
                panic!("TODO: Handle case where block is already in replica; \
                        (should just ignore and make a log entry)."),
            Err(AppendErr::MissingBlocksSince(after_block_hash)) => {
                let blocks_req = BlocksRequest::new(node.inst_addr,
                    after_block_hash, self.our_inst_addr, &our_secret_key);
                return node.send(NetPayload::BlocksReq(blocks_req))
            },
            Err(AppendErr::BlockParentAlreadyClaimed) =>
                panic!("TODO: Handle case where block parent is already claimed."),
            Err(AppendErr::ChainStateCorrupted) =>
                panic!("TODO: Handle corrupted chain state.")
        };
    }

    pub fn handle_sigresp(&mut self,
                          sigresp: SignatureResponse,
                          fsm: Arc<RwLock<FSM>>)
            -> std::io::Result<()> {

        // Ensure that we have confirmed the authoring node's
        // identity.
        if !self.is_confirmed_node(&sigresp.from_inst_addr) {
            return Err(io::Error::new(io::ErrorKind::Other,
                format!("Ignoring sigresp from {}; their identity
                         has not been confirmed.",
                         &sigresp.from_inst_addr)));
        }

        // Get the node (we can unwrap due to above check);
        let mut node_map = self.node_map.write().unwrap();
        let mut node = node_map.get_mut(&sigresp.from_inst_addr).unwrap();

        // Next, get the most recent sigreq we've sent to this node.
        match node.awaiting_sigreq {
            Some(ref sigreq) => {
                // Check the validity of the response against the sigreq.
                if let Err(err) = sigresp.check_validity(sigreq,
                                                        &self.our_inst_addr) {
                    panic!("TODO: Log invalid sigresp: {:?}", err)
                }
            },
            None => {
                warn!("Ignoring sigresp from {}; we never \
                       sent out a sigreq for this institution.",
                       &sigresp.from_inst_addr);
                return Ok(())
            }
        };

        node.awaiting_sigreq = None;
        let ref mut fsm = *fsm.write().unwrap();
        fsm.push_state(FSMState::AddSignatureToProcessingBlock(
                sigresp.from_inst_addr, sigresp.block_header_hash_signature));
        fsm.push_state(FSMState::SyncHashchainToDisk);
        Ok(())
    }

    pub fn handle_peerreq(&mut self,
            peer_req: PeerRequest) -> std::io::Result<()> {

        // Determine if the contents of this request are valid.
        if let Err(_) = peer_req.check_validity(&self.our_inst_addr) {
            panic!("TODO: Log invalid peer request.")
        }

        // Ensure that we have confirmed the node's identity.
        // TODO: If we have not, rather than ignore the request,
        // connnect and request their identity, and queue the
        // peer request for processing once this has been done.
        if !self.is_confirmed_node(&peer_req.from_inst_addr) {
            return Err(io::Error::new(io::ErrorKind::Other,
                format!("Ignoring peer request from node {}; their \
                         identity has not been confirmed.",
                         &peer_req.from_inst_addr)));
        }

        // Get the node (we can unwrap due to above check).
        let mut node_map = self.node_map.write().unwrap();
        let mut node = node_map.get_mut(&peer_req.from_inst_addr).unwrap();

        // Adjust peering state accordingly.
        node.our_peering_approval = PeeringApproval::AwaitingOurApproval;
        Ok(())
    }

    pub fn approve_peerreq(&mut self,
            inst_addr: InstAddress,
            fsm: Arc<RwLock<FSM>>) -> std::io::Result<()> {

        // First, ensure that we have confirmed the node's identity.
        if !self.is_confirmed_node(&inst_addr) {
            return Err(io::Error::new(io::ErrorKind::Other,
                "The peer's identity has not been confirmed."));
        }

        // Second, get the node (we can unwrap due to above check).
        let mut node_map = self.node_map.write().unwrap();
        let mut node = node_map.get_mut(&inst_addr).unwrap();

        // Third, ensure that this node is actually awaiting approval
        // of a peering relationship.
        if node.our_peering_approval != PeeringApproval::AwaitingOurApproval {
            return Err(io::Error::new(io::ErrorKind::Other,
                "The peer is not awaiting your approval."));
        }

        // Fourth, adjust peering state accordingly.
        node.our_peering_approval = PeeringApproval::Approved;
        let ref mut fsm = *fsm.write().unwrap();
        fsm.push_state(FSMState::SyncNodeTableToDisk);

        // Finally, have the FSM queue a new block containing the action
        // and sync the queued block to disk.
        fsm.push_state(FSMState::QueueNewBlock(vec![
                Action::AddPeer(node.inst_addr,
                node.hostname.clone(), node.port)]));
        fsm.push_state(FSMState::SyncHashchainToDisk);
        Ok(())
    }

    pub fn end_peering(&mut self, inst_addr: InstAddress,
                       hashchain: Arc<RwLock<Hashchain>>,
                       fsm: Arc<RwLock<FSM>>) -> std::io::Result<()> {

        // Get the peer.
        let mut node_map = self.node_map.write().unwrap();
        let mut node = node_map.get_mut(&inst_addr).unwrap();

        // If removing this peer will result in the institution having
        // zero peers, abort and inform the user.
        let ref hashchain = *hashchain.read().unwrap();
        let action = Action::RemovePeer(node.inst_addr);
        if hashchain.get_signoff_peers(&vec![action.clone()]).len() == 0 {
            return Err(io::Error::new(io::ErrorKind::Other,
                    "You must have at least one peer at all times. \
                     Add another peer first before removing this one."));
        }

        // Downgrade peering approval.
        node.our_peering_approval = PeeringApproval::NotApproved;
        let ref mut fsm = *fsm.write().unwrap();
        fsm.push_state(FSMState::SyncNodeTableToDisk);

        // Have the FSM queue a new block containing the action
        // and sync the queued block to disk.
        fsm.push_state(FSMState::QueueNewBlock(vec![action]));
        fsm.push_state(FSMState::SyncHashchainToDisk);
        Ok(())
    }

    pub fn send_block_manifest(&mut self,
                               inst_addr: &InstAddress,
                               manifest: BlockManifest) -> std::io::Result<()> {
        let mut node_map = self.node_map.write().unwrap();
        match node_map.get_mut(inst_addr) {
            Some(node) => {
                node.send(NetPayload::BlockManifest(manifest))
            },
            None => Err(io::Error::new(io::ErrorKind::Other,
                    format!("Node {} is not registered, can't send manifest.",
                    inst_addr))),
        }
    }

    /// When handling block manifests, we don't care who the sender is,
    /// we just care that 1) the block is authored by one of our peers,
    /// and 2) that the block is valid and has not been manipulated.
    pub fn handle_block_manifest(&mut self,
                                 mf: BlockManifest,
                                 fsm: Arc<RwLock<FSM>>) -> std::io::Result<()> {
        // Ensure that we have confirmed the authoring node's
        // identity.
        if !self.is_confirmed_node(&mf.block.header.author) {
            return Err(io::Error::new(io::ErrorKind::Other,
                format!("Ignoring block manifest with block authored by \
                         {}; their identity has not been confirmed.",
                         &mf.block.header.author)));
        }

        // Get the node (we can unwrap due to above check).
        let mut node_map = self.node_map.write().unwrap();
        let mut node = node_map.get_mut(&mf.block.header.author).unwrap();

        // Ensure that peering has been approved with the authoring
        // institution.
        let ref hc_replica = node.lazy_load_replica(&self.replica_dir);
        match node.our_peering_approval {
            PeeringApproval::Approved => {
                let res = hc_replica.write().unwrap()
                        .is_block_eligible_for_append(&mf.block,
                                                      RequireAllPeerSigs::Yes);
                match res {
                    Ok(_) => {
                        hc_replica.write().unwrap().append_block(mf.block);
                        let ref mut fsm = *fsm.write().unwrap();
                        fsm.push_state(
                            FSMState::SyncReplicaToDisk(node.inst_addr));
                        Ok(())
                    },
                    Err(AppendErr::MissingBlocksSince(_)) =>
                        panic!("TODO: Peer's replica is missing blocks; \
                                sync up with them."),
                    Err(AppendErr::BlockAlreadyInChain) => {
                        info!("Ignoring block in manifest; already in chain.");
                        Ok(())
                    },
                    Err(e @ AppendErr::AuthorSignatureInvalid)
                    | Err(e @ AppendErr::NoSignoffPeersListed)
                    | Err(e @ AppendErr::MissingPeerSignature)
                    | Err(e @ AppendErr::InvalidPeerSignature)
                    | Err(e @ AppendErr::BlockParentAlreadyClaimed)
                    | Err(e @ AppendErr::UnexpectedSignoffPeers)
                    | Err(e @ AppendErr::UnexpectedSignoffPeersHash)
                    | Err(e @ AppendErr::InvalidActionFound(_))
                    | Err(e @ AppendErr::UnexpectedMerkleRootHash) => {
                        panic!("TODO: Peer has equivocated; set flag and \
                                stop processing replica updates: {:?}", e);
                    },
                    Err(AppendErr::ChainStateCorrupted) =>
                        panic!("TODO: Peer's replica is corrupted; determine \
                                 why."),
                }
            },
            _ => {
                info!("Ignoring block manifest with block authored by \
                       {}; we have not approved a peering relationship \
                       with them.", &mf.block.header.author);
                Ok(())
            }
        }
    }

    pub fn is_confirmed_node(&self, node_addr: &InstAddress) -> bool {
        let node_map = self.node_map.read().unwrap();
        match node_map.get(node_addr) {
            Some(p) => {
                p.ident_state == IdentityState::Confirmed
            }
            None => false
        }
    }

    pub fn write_replica_to_disk(&self, node_addr: &InstAddress)
            -> std::io::Result<()> {
        let node_map = self.node_map.read().unwrap();
        match node_map.get(node_addr) {
            Some(node) => {
                node.write_replica_to_disk(&self.replica_dir);
                Ok(())
            },
            None => Err(io::Error::new(io::ErrorKind::Other,
                    format!("Node {} is not registered, \
                            can't write replica to disk.",
                    node_addr))),
        }
    }
}

/*
 * Unlike the other requests and respones, block manifests are
 * intended to be disemminated broadly by anyone in support
 * of efficient and public replication, so
 * message signatures, nonces, and addresses are not required here.
 */
impl BlockManifest {
    pub fn new(block: Block) -> BlockManifest {
        BlockManifest {
            block: block
        }
    }
}

impl NetNode {
    pub fn new(inst_addr: InstAddress, hostname: &String,
               port: u16, our_peering_approval: PeeringApproval) -> NetNode {
        NetNode {
            inst_addr: inst_addr,
            hostname: String::from(&hostname[..]),
            port: port,
            socket: Socket::new(),
            conn_state: ConnectionState::NotConnected,
            ident_state: IdentityState::NotConfirmed,
            our_peering_approval: our_peering_approval,
            identreq: None,
            identresp: None,
            awaiting_sigreq: None,
            hc_replica: None,
        }
    }

    /// Replicas of other institutions' hashchains are loaded lazily;
    /// if no hashchain replica file is found for an institution,
    /// a new hashchain is used.
    fn lazy_load_replica(&mut self,
                         replica_dir: &String) -> Arc<RwLock<Hashchain>> {
        let hc_replica = match self.hc_replica {
            Some(ref replica) => replica.clone(),
            None => {
                let replica_path = format!("{}/{}.dat",
                                           replica_dir, self.inst_addr);
                match File::open(&replica_path) {
                    Ok(file) => {
                        let raw: Hashchain =
                            serde_json::from_reader(file).unwrap();
                        Arc::new(RwLock::new(raw))
                    },
                    Err(_) => {
                        info!("Unable to open replica file {}; starting \
                               new chain.", replica_path);
                        Arc::new(RwLock::new(Hashchain::new()))
                    }
                }
            }
        };
        self.hc_replica = Some(hc_replica.clone());
        hc_replica
    }

    fn write_replica_to_disk(&self, replica_dir: &String) {
        let replica_path = format!("{}/{}.dat", replica_dir, self.inst_addr);
        let mut writer = BufWriter::new(File::create(&replica_path).unwrap());
        let ref replica = *self.hc_replica.as_ref().unwrap().read().unwrap();
        serde_json::to_writer_pretty(&mut writer, replica).unwrap();
    }

    pub fn to_disk(&self) -> OnDiskNetNode {
        OnDiskNetNode {
            inst_addr: self.inst_addr.to_base58(),
            hostname: String::from(&self.hostname[..]),
            port: self.port,
            our_peering_approval: self.our_peering_approval.clone(),
        }
    }

    pub fn connect(&mut self) -> std::io::Result<()> {
        match self.conn_state {
            ConnectionState::NotConnected => {
                info!("Attempting to connect to node {}...", self);
                match self.socket.connect(&self.hostname[..], self.port) {
                    Ok(_) => {
                        info!("Connected to node {}.", self);
                        self.conn_state = ConnectionState::Connected;
                        Ok(())
                    },
                    Err(err) => {
                        self.conn_state = ConnectionState::NotConnected;
                        Err(io::Error::new(io::ErrorKind::NotConnected,
                            format!("Unable to connect to node {}; \
                                    error is: {}", self, err)))
                    }
                }
            },
            _ => {
                info!("We are already connected to {}; ignoring \
                        connect call.", self);
                Ok(())
            }
        }
    }

    pub fn send(&mut self, payload: NetPayload) -> std::io::Result<()> {

        // If we're not connected to this node, try once to connect
        // before sending.
        if self.conn_state == ConnectionState::NotConnected {
            let _ = self.connect();
        }

        // If we're still not connected, give up.
        if self.conn_state == ConnectionState::NotConnected {
            return Err(io::Error::new(io::ErrorKind::NotConnected,
                "Unable to send payload to disconnected node."));
        }

        match self.ident_state {
            IdentityState::NotConfirmed => {
                match payload {
                    NetPayload::IdentReq(_) |
                    NetPayload::IdentResp(_) => {
                        self.socket.send(NetworkMessage::new(payload))
                    },
                    _ => {
                        panic!("Encountered attempt to send non-identity-related \
                                message to an unconfirmed node: {:?}", payload)
                    }
                }
            }
            IdentityState::Confirmed =>
                self.socket.send(NetworkMessage::new(payload))
        }
    }
}

impl Display for NetNode {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        try!(write!(f, "NetNode[{}, {}:{}]", self.inst_addr,
                    self.hostname, self.port));
        Ok(())
    }
}

impl BlocksRequest {
    pub fn new(to_inst_addr: InstAddress,
               after_block_hash: DoubleSha256Hash,
               our_inst_addr: InstAddress,
               our_secret_key: &SecretKey) -> BlocksRequest {
        let to_hash = format!("BLOCKSREQUEST:{},{},{}", to_inst_addr,
                              our_inst_addr, after_block_hash);
        BlocksRequest {
            to_inst_addr: to_inst_addr,
            from_inst_addr: our_inst_addr,
            after_block_hash: after_block_hash,
            from_signature: RecovSignature::sign(
                &DoubleSha256Hash::hash(&to_hash.as_bytes()[..]),
                &our_secret_key)
        }
    }
    pub fn check_validity(&self, our_addr: &InstAddress)
            -> Result<(), ValidityErr> {
        panic!("TODO: Implement check_validity for BlocksRequest.");
    }
}

impl SignatureRequest {
    pub fn new(to_inst_addr: InstAddress,
               block: Block, our_secret_key: &SecretKey) -> SignatureRequest {
        let mut crypto_rng = OsRng::new().unwrap();
        let nonce = crypto_rng.gen::<u64>();
        /*
         * TODO: This signature needs to tie in the block as well;
         * when block header is added, add the hash of the header to the sig.
         */
        let to_hash = format!("SIGREQ:{}", nonce);
        SignatureRequest {
            nonce: nonce,
            to_inst_addr: to_inst_addr,
            block: block,
            from_signature: RecovSignature::sign(
                &DoubleSha256Hash::hash(&to_hash.as_bytes()[..]),
                &our_secret_key)
        }
    }

    /// It's important to note that this method does NOT validate
    /// the block within the signature request. It only validates
    /// the request itself (and ensures that it is signed by the
    /// same node that authored the block within).
    pub fn check_validity(&self, our_addr: &InstAddress)
            -> Result<(), ValidityErr> {
        // Check individual fields.
        if let Err(_) = self.to_inst_addr.check_validity() {
            return Err(ValidityErr::ToInstAddrInvalid);
        }
        if self.to_inst_addr != *our_addr {
            return Err(ValidityErr::ToInstAddrDoesntMatchOurs);
        }

        // Check signature validity.
        let expected_msg = &DoubleSha256Hash::hash(
            &format!("SIGREQ:{}", self.nonce).as_bytes()[..]);
        self.from_signature.check_validity(&expected_msg,
                                           &self.block.header.author)
    }
}

impl SignatureResponse {
    fn new(request_nonce: u64,
           to_inst_addr: InstAddress,
           our_inst_addr: InstAddress,
           block_header_hash: DoubleSha256Hash,
           our_secret_key: &SecretKey) -> SignatureResponse {
        let block_sig = RecovSignature::sign(&block_header_hash, &our_secret_key);
        let resp_sig_hash = format!("SIGRESP:{},{},{},{},{}",
                request_nonce, to_inst_addr,
                our_inst_addr, block_header_hash, block_sig);
        SignatureResponse {
            nonce: request_nonce,
            to_inst_addr: to_inst_addr,
            from_inst_addr: our_inst_addr,
            block_header_hash: block_header_hash,
            block_header_hash_signature: block_sig,
            from_signature: RecovSignature::sign(
                &DoubleSha256Hash::hash(&resp_sig_hash.as_bytes()[..]),
                &our_secret_key)
        }
    }

    fn check_validity(&self, sigreq: &SignatureRequest,
                      our_inst_addr: &InstAddress) -> Result<(), ValidityErr> {
        // Check individual fields.
        if self.nonce != sigreq.nonce {
            return Err(ValidityErr::NonceDoesntMatch);
        }
        if let Err(_) = self.to_inst_addr.check_validity() {
            return Err(ValidityErr::ToInstAddrInvalid);
        }
        if self.to_inst_addr != *our_inst_addr {
            return Err(ValidityErr::ToInstAddrDoesntMatchOurs);
        }
        if let Err(_) = self.from_inst_addr.check_validity() {
            return Err(ValidityErr::FromInstAddrInvalid);
        }
        if self.from_inst_addr != sigreq.to_inst_addr {
            return Err(ValidityErr::FromInstAddrDoesntMatchRequest);
        }
        if self.block_header_hash != sigreq.block.header.hash() {
            return Err(ValidityErr::SignedBlockHeaderHashDoesntMatchRequest);
        }

        // Check validity of message signature.
        let expected_msg = &DoubleSha256Hash::hash(&format!(
                "SIGRESP:{},{},{},{},{}", self.nonce, self.to_inst_addr,
                self.from_inst_addr, self.block_header_hash,
                self.block_header_hash_signature).as_bytes()[..]);
        try!(self.from_signature.check_validity(&expected_msg,
                                                &self.from_inst_addr));

        // Check validity of block header signature.
        self.block_header_hash_signature.check_validity(&self.block_header_hash,
                                           &self.from_inst_addr)
    }
}

impl IdentityRequest {
    fn new(to_node: &NetNode,
               our_inst_addr: InstAddress,
               our_hostname: &str,
               our_port: u16,
               our_secret_key: &SecretKey) -> IdentityRequest {
        let mut crypto_rng = OsRng::new().unwrap();
        let nonce = crypto_rng.gen::<u64>();
        let to_hash = format!("IDENTREQ:{},{},{},{}", nonce, our_inst_addr,
                              our_hostname, our_port);
        IdentityRequest {
            nonce: nonce,
            to_inst_addr: to_node.inst_addr,
            to_hostname: String::from(&to_node.hostname[..]),
            to_port: to_node.port,
            from_inst_addr: our_inst_addr,
            from_hostname: String::from(our_hostname),
            from_port: our_port,
            from_signature: RecovSignature::sign(
                &DoubleSha256Hash::hash(&to_hash.as_bytes()[..]),
                &our_secret_key)
        }
    }

    fn check_validity(&self, our_addr: &InstAddress,
            our_hostname: &String, our_port: &u16) -> Result<(), ValidityErr> {
        // Check individual fields.
        if let Err(_) = self.to_inst_addr.check_validity() {
            return Err(ValidityErr::ToInstAddrInvalid);
        }
        if self.to_inst_addr != *our_addr {
            return Err(ValidityErr::ToInstAddrDoesntMatchOurs);
        }
        if self.to_hostname != *our_hostname {
            return Err(ValidityErr::ToHostNameDoesntMatchOurs);
        }
        if self.to_port != *our_port {
            return Err(ValidityErr::ToPortDoesntMatchOurs);
        }
        if let Err(_) = self.from_inst_addr.check_validity() {
            return Err(ValidityErr::FromInstAddrInvalid);
        }

        // Check signature validity.
        let expected_msg = &DoubleSha256Hash::hash(
            &format!("IDENTREQ:{},{},{},{}", self.nonce, self.from_inst_addr,
                    self.from_hostname, self.from_port).as_bytes()[..]);
        self.from_signature.check_validity(&expected_msg, &self.from_inst_addr)
    }
}

impl IdentityResponse {
    fn new(our_inst_addr: InstAddress, request_nonce: u64,
            our_secret_key: &SecretKey) -> IdentityResponse {
        let to_hash = format!("IDENTRESP:{},{}", request_nonce, our_inst_addr);
        IdentityResponse {
            nonce: request_nonce,
            from_inst_addr: our_inst_addr,
            from_signature: RecovSignature::sign(
                &DoubleSha256Hash::hash(&to_hash.as_bytes()[..]),
                &our_secret_key)
        }
    }

    fn check_validity(&self, identreq: &IdentityRequest)
            -> Result<(), ValidityErr> {
        // Check individual fields.
        if self.nonce != identreq.nonce {
            return Err(ValidityErr::NonceDoesntMatch);
        }
        if let Err(_) = self.from_inst_addr.check_validity() {
            return Err(ValidityErr::FromInstAddrInvalid);
        }

        // Check signature validity.
        let expected_msg = &DoubleSha256Hash::hash(&format!("IDENTRESP:{},{}",
            self.nonce, self.from_inst_addr).as_bytes()[..]);
        self.from_signature.check_validity(&expected_msg, &self.from_inst_addr)
    }
}

impl NetworkMessage {
    pub fn new(payload: NetPayload) -> NetworkMessage {
        let mut adler = adler::State32::new();
        let mut payload_bytes = Vec::new();
        payload.encode(&mut msgpack::Encoder::new(&mut payload_bytes)).unwrap();
        adler.feed(&payload_bytes[..]);
        NetworkMessage {
            magic: MAINNET_MSG_MAGIC,
            payload: payload,
            payload_checksum: adler.result()
        }
    }
}

impl PeerRequest {
    fn new(to_inst_addr: InstAddress,
           our_inst_addr: InstAddress,
           our_secret_key: &SecretKey) -> PeerRequest {
        let mut crypto_rng = OsRng::new().unwrap();
        let nonce = crypto_rng.gen::<u64>();
        let to_hash = format!("PEERREQ:{},{},{}", nonce, to_inst_addr,
                              our_inst_addr);
        PeerRequest {
            nonce: nonce,
            to_inst_addr: to_inst_addr,
            from_inst_addr: our_inst_addr,
            from_signature: RecovSignature::sign(
                &DoubleSha256Hash::hash(&to_hash.as_bytes()[..]),
                &our_secret_key)
        }
    }

    fn check_validity(&self,
                our_addr: &InstAddress) -> Result<(), ValidityErr> {
        // Check individual fields.
        if let Err(_) = self.to_inst_addr.check_validity() {
            return Err(ValidityErr::ToInstAddrInvalid);
        }
        if let Err(_) = self.from_inst_addr.check_validity() {
            return Err(ValidityErr::FromInstAddrInvalid);
        }
        if self.to_inst_addr != *our_addr {
            return Err(ValidityErr::ToInstAddrDoesntMatchOurs);
        }

        // Check signature validity.
        let expected_msg = &DoubleSha256Hash::hash(&format!("PEERREQ:{},{},{}",
            self.nonce, self.to_inst_addr, self.from_inst_addr).as_bytes()[..]);
        self.from_signature.check_validity(&expected_msg, &self.from_inst_addr)
    }
}

impl Socket {

    pub fn new() -> Socket {
        Socket {
            tcp_sock: Arc::new(Mutex::new(None)),
        }
    }

    pub fn connect(&mut self, hostname: &str, port: u16)
            -> std::io::Result<()> {
        match TcpStream::connect((hostname, port)) {
            Ok(sock) => {
                self.tcp_sock = Arc::new(Mutex::new(Some(sock)));
                Ok(())
            },
            Err(err) => {
                self.tcp_sock = Arc::new(Mutex::new(None));
                Err(err)
            }
        }
    }

    pub fn send(&self, net_msg: NetworkMessage) -> std::io::Result<()> {
        match self.tcp_sock.lock() {
            Err(_) => {
                Err(io::Error::new(io::ErrorKind::NotConnected,
                                   "Socket mutex is poisoned."))
            },
            Ok(mut guard) => {
                match *guard.deref_mut() {
                    Some(ref mut tcp_stream) => {
                        debug!("Writing out net msg to socket.");
                        let mut buf_writer = BufWriter::new(tcp_stream);
                        net_msg.encode(&mut msgpack::Encoder::new(&mut buf_writer)).unwrap();
                        Ok(())
                    },
                    None => {
                        Err(io::Error::new(io::ErrorKind::NotConnected,
                                           "Socket not connected to node."))
                    }
                }
            }
        }
    }

    pub fn receive(&self) -> std::io::Result<NetworkMessage> {
        match self.tcp_sock.lock() {
            Err(_) => {
                Err(io::Error::new(io::ErrorKind::NotConnected,
                                   "Socket mutex is poisoned."))
            },
            Ok(mut guard) => {
                match *guard.deref_mut() {
                    Some(ref mut tcp_stream) => {
                        let buf_reader = BufReader::new(tcp_stream);
                        let mut decoder = msgpack::Decoder::new(buf_reader);
                        let net_msg: NetworkMessage
                                = match Decodable::decode(&mut decoder) {
                            Ok(msg) => msg,
                            Err(err) => return Err(io::Error::new(
                                    io::ErrorKind::Other, err))
                        };

                        // Ensure that the message's magic matches expected value.
                        if net_msg.magic != MAINNET_MSG_MAGIC {
                            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                    format!("Expected magic {}, msg has magic {}.",
                                    MAINNET_MSG_MAGIC,
                                    net_msg.magic)))
                        }

                        // Ensure that the message payload matches the checksum.
                        let mut adler = adler::State32::new();
                        let mut payload_bytes = Vec::new();
                        net_msg.payload.encode(&mut msgpack::Encoder::new(
                                &mut payload_bytes)).unwrap();
                        adler.feed(&payload_bytes[..]);
                        let gen_checksum = adler.result();
                        if net_msg.payload_checksum != gen_checksum {
                            return Err(io::Error::new(io::ErrorKind::InvalidData,
                                    format!("Expected payload checksum {}, \
                                    msg payload has checksum {}.",
                                    net_msg.payload_checksum, gen_checksum)))
                        }

                        // If all checks pass, message is intact.
                        Ok(net_msg)
                    },
                    None => {
                        Err(io::Error::new(io::ErrorKind::NotConnected,
                                           "Socket not connected to node."))
                    }
                }
            }
        }
    }
}

pub fn listen(payload_tx: Sender<NetPayload>,
              config: &CertChainConfig) {

    // Start listening on the listener port in the provided config.
    let listener_port: &u16 = &config.port;
    let listener = match TcpListener::bind(
            (&"0.0.0.0"[..], *listener_port)) {
        Ok(listener) => {
            info!("Successfully established listener on port {}.",
                  listener_port);
            listener
        },
        Err(e) => panic!("Unable to listen on port {}: {}",
                         listener_port, e),
    };

    let payload_tx_clone1 = payload_tx.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let payload_tx_clone2 = payload_tx_clone1.clone();
                    thread::spawn(move || {
                        let recv_sock = Socket {
                            tcp_sock: Arc::new(Mutex::new(Some(stream))),
                        };
                        loop {
                            match recv_sock.receive() {
                                Ok(net_msg) => {
                                    debug!("Received message from node: {:?}", net_msg);
                                    payload_tx_clone2.send(net_msg.payload).unwrap();
                                },
                                Err(_) => {
                                    info!("Client disconnected; exiting listener thread.");
                                    break;
                                }
                            }
                        }
                    });
                },
                Err(e) => warn!("Ignoring client request due to error: {}", e)
            }
        }
    });
}

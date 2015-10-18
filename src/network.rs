use std::net::{TcpListener, TcpStream};
use std::io;
use std;
use config::CertChainConfig;
use std::thread;
use std::sync::{Arc, RwLock, Mutex};
use std::sync::mpsc::{Sender};
use std::ops::DerefMut;
use std::io::{Write, BufReader, BufWriter};
use rustc_serialize::{Encodable, Decodable};
use msgpack::{Encoder, Decoder};
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
use std::collections::HashMap;

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
}

struct NetPeer {
    inst_addr: InstAddress,
    hostname: String,
    port: u16,
    socket: Socket,
    conn_state: ConnectionState,
    identreq: Option<IdentityRequest>,
    identresp: Option<IdentityResponse>
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

#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct IdentityResponse {
    pub nonce: u64,
    pub from_inst_addr: InstAddress,
    pub from_signature: RecovSignature,
}

#[derive(Debug)]
enum ConnectionState {
    NotConnected,
    ConnectedIdentityConfirmed,
    ConnectedIdentityUnconfirmed,
}

pub struct NetPeerTable {
    peer_map: Arc<RwLock<HashMap<InstAddress, NetPeer>>>,
    our_inst_addr: InstAddress,
    our_hostname: String,
    our_port: u16,
}

impl NetPeerTable {
    pub fn new(config: &CertChainConfig) -> NetPeerTable {
        let inst_pubkey = key::compressed_public_key_from_string(
                &config.compressed_public_key).unwrap();
        let inst_addr = InstAddress::from_pubkey(&inst_pubkey).unwrap();
        info!("This node is peering as {}.", inst_addr);
        NetPeerTable {
            peer_map: Arc::new(RwLock::new(HashMap::new())),
            our_inst_addr: inst_addr,
            our_hostname: String::from(&config.hostname[..]),
            our_port: config.port,
        }
    }

    /// Register's an institution as a peer based on their institutional address,
    /// and initiates a TCP connection to them.
    pub fn register(&mut self, peer_addr: InstAddress,
            hostname: &String, port: u16) {
        let mut peer_map = self.peer_map.write().unwrap();
        match peer_map.get(&peer_addr) {
            Some(_) => info!("Already peering with {}; \
                             ignorning call to register it.", peer_addr),
            None => {
                let mut peer = NetPeer::new(peer_addr, hostname, port);
                peer.connect().unwrap();
                peer_map.insert(peer_addr, peer);
            }
        }
    }

    pub fn send_identreq(&mut self, peer_addr: InstAddress,
            our_secret_key: &SecretKey) -> std::io::Result<()> {
        let mut peer_map = self.peer_map.write().unwrap();
        match peer_map.get_mut(&peer_addr) {
            Some(peer) => {
                let identreq = IdentityRequest::new(&peer,
                        self.our_inst_addr,
                        &self.our_hostname[..],
                        self.our_port,
                        &our_secret_key);
                match peer.send(NetPayload::IdentReq(identreq.clone())) {
                    Ok(_) => {
                        peer.identreq = Some(identreq);
                        Ok(())
                    },
                    Err(err) => Err(err)
                }
            },
            None => Err(io::Error::new(io::ErrorKind::Other,
                    format!("Peer {} is not registered, can't request identity.",
                    peer_addr))),
        }
    }

    pub fn handle_identreq(&mut self, identreq: IdentityRequest,
            our_secret_key: &SecretKey) -> std::io::Result<()> {
        // First, determine if the contents of this request are valid.
        if let Err(_) = identreq.check_validity(&self.our_inst_addr,
                &self.our_hostname, &self.our_port) {
            panic!("TODO: Log invalid ident req.")
        }

        // Second, ensure this peer is registered, then get the peer.
        self.register(identreq.from_inst_addr,
                &identreq.from_hostname, identreq.from_port);
        let mut peer_map = self.peer_map.write().unwrap();
        let mut peer = peer_map.get_mut(&identreq.from_inst_addr).unwrap();

        // Third, create a response and send to the peer.
        let identresp = IdentityResponse::new(self.our_inst_addr,
                identreq.nonce, &our_secret_key);
        peer.send(NetPayload::IdentResp(identresp))
    }

    pub fn process_identresp(&mut self, identresp: IdentityResponse)
            -> std::io::Result<()> {
        // First, ensure that we actually have a peer matching that
        // of the responding institution.
        let mut peer_map = self.peer_map.write().unwrap();
        let mut peer = match peer_map.get_mut(&identresp.from_inst_addr) {
            Some(p) => p,
            None => {
                warn!("Ignoring identresp from {}; we are \
                       not peering with this institution.",
                       &identresp.from_inst_addr);
                return Ok(())
            }
        };

        // Next, ensure that we sent out an identity request for this peer.
        let identreq = match peer.identreq {
            Some(ref req) => req,
            None => {
                warn!("Ignoring identresp from {}; we never \
                       sent out an identreq for this institution.",
                       peer.inst_addr);
                return Ok(())
            }
        };

        // Third, check the validity of the response's nonce and signature.
        if let Err(_) = identresp.check_validity(identreq) {
            panic!("TODO: Log invalid identresp.")
        }

        // Now that all checks passed, elevate the peer's identity status
        // to confirmed.
        peer.conn_state = ConnectionState::ConnectedIdentityConfirmed;
        peer.identresp = Some(identresp);
        info!("Peer {} has confirmed their identity to us.", peer.inst_addr);
        Ok(())
    }
}

impl NetPeer {
    pub fn new(inst_addr: InstAddress, hostname: &String, port: u16) -> NetPeer {
        NetPeer {
            inst_addr: inst_addr,
            hostname: String::from(&hostname[..]),
            port: port,
            socket: Socket::new(),
            conn_state: ConnectionState::NotConnected,
            identreq: None,
            identresp: None,
        }
    }

    pub fn connect(&mut self) -> std::io::Result<()> {
        match self.conn_state {
            ConnectionState::NotConnected => {
                info!("Connecting to peer {}...", self);
                match self.socket.connect(&self.hostname[..], self.port) {
                    Ok(_) => {
                        info!("Connected to peer {}.", self);
                        self.conn_state =
                            ConnectionState::ConnectedIdentityUnconfirmed;
                        Ok(())
                    },
                    Err(err) => {
                        self.conn_state = ConnectionState::NotConnected;
                        Err(io::Error::new(io::ErrorKind::NotConnected,
                            format!("Unable to connect to peer {}; \
                                    error is: {}", self, err)))
                    }
                }
            },
            _ => Err(io::Error::new(io::ErrorKind::AlreadyExists,
                    format!("Peer's connection state is {:?}.", self.conn_state)))
        }
    }

    pub fn send(&mut self, payload: NetPayload) -> std::io::Result<()> {

        // If we're not connected to this peer, try one to connect
        // before sending.
        if let ConnectionState::NotConnected = self.conn_state {
            self.connect().unwrap();
        }

        match self.conn_state {
            ConnectionState::NotConnected =>
                Err(io::Error::new(io::ErrorKind::NotConnected,
                    "Unable to send payload to disconnected peer.")),
            ConnectionState::ConnectedIdentityUnconfirmed => {
                match payload {
                    NetPayload::IdentReq(_) |
                    NetPayload::IdentResp(_) => {
                        self.socket.send(NetworkMessage::new(payload))
                    },
                    /*_ => Err(io::Error::new(io::ErrorKind::Other,
                        "Attempted to send a non-identity msg to a peer \
                         whose identity is not yet confirmed."))*/
                }
            },
            ConnectionState::ConnectedIdentityConfirmed =>
                // TODO: When peer is confirmed, do not send identity req.
                panic!("TODO: Send payload to confirmed peer.")
        }
    }
}

impl Display for NetPeer {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        try!(write!(f, "NetPeer[{}, {}:{}]", self.inst_addr,
                    self.hostname, self.port));
        Ok(())
    }
}

impl IdentityRequest {
    fn new(to_peer: &NetPeer,
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
            to_inst_addr: to_peer.inst_addr,
            to_hostname: String::from(&to_peer.hostname[..]),
            to_port: to_peer.port,
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

        /*
         * Reconstruct the expected signature message and attempt to
         * recover the public key from the signature. If it succeeds *and*
         * the pubkey hashes to the sending institution address, we're good.
         */
        let from_combined = format!("IDENTREQ:{},{},{},{}", self.nonce, self.from_inst_addr,
                              self.from_hostname, self.from_port);
        let from_hash = &DoubleSha256Hash::hash(&from_combined.as_bytes()[..]);
        let from_pubkey_recov = match self.from_signature
                .recover_pubkey(&from_hash) {
            Ok(pubkey) => pubkey,
            Err(_) => return Err(ValidityErr::UnableToRecoverFromAddrPubkey),
        };
        let from_addr_recov = match InstAddress::from_pubkey(&from_pubkey_recov) {
            Ok(addr) => addr,
            Err(_) => return Err(ValidityErr::RecoveredFromAddrInvalid)
        };
        if self.from_inst_addr != from_addr_recov {
            return Err(ValidityErr::RecoveredFromAddrDoesntMatch)
        }
        return Ok(())
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
        if self.nonce != identreq.nonce {
            return Err(ValidityErr::NonceDoesntMatch);
        }
        if let Err(_) = self.from_inst_addr.check_validity() {
            return Err(ValidityErr::FromInstAddrInvalid);
        }

        /*
         * Reconstruct the expected signature message and attempt to
         * recover the public key from the signature. If it succeeds *and*
         * the pubkey hashes to the sending institution address, we're good.
         */
        let from_combined = format!("IDENTRESP:{},{}", self.nonce,
                                    self.from_inst_addr);
        let from_hash = &DoubleSha256Hash::hash(&from_combined.as_bytes()[..]);
        let from_pubkey_recov = match self.from_signature
                .recover_pubkey(&from_hash) {
            Ok(pubkey) => pubkey,
            Err(_) => return Err(ValidityErr::UnableToRecoverFromAddrPubkey),
        };
        let from_addr_recov = match InstAddress::from_pubkey(&from_pubkey_recov) {
            Ok(addr) => addr,
            Err(_) => return Err(ValidityErr::RecoveredFromAddrInvalid)
        };
        if self.from_inst_addr != from_addr_recov {
            return Err(ValidityErr::RecoveredFromAddrDoesntMatch)
        }
        return Ok(())
    }
}

impl NetworkMessage {
    pub fn new(payload: NetPayload) -> NetworkMessage {
        let mut adler = adler::State32::new();
        let mut payload_bytes = Vec::new();
        payload.encode(&mut Encoder::new(&mut payload_bytes)).unwrap();
        adler.feed(&payload_bytes[..]);
        NetworkMessage {
            magic: MAINNET_MSG_MAGIC,
            payload: payload,
            payload_checksum: adler.result()
        }
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
                        net_msg.encode(&mut Encoder::new(&mut buf_writer)).unwrap();
                        Ok(())
                    },
                    None => {
                        Err(io::Error::new(io::ErrorKind::NotConnected,
                                           "Socket not connected to peer."))
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
                        let mut decoder = Decoder::new(buf_reader);
                        let net_msg: NetworkMessage =
                            Decodable::decode(&mut decoder).unwrap();

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
                        net_msg.payload.encode(&mut Encoder::new(&mut payload_bytes)).unwrap();
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
                                           "Socket not connected to peer."))
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
                                    debug!("Received message from peer: {:?}", net_msg);
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

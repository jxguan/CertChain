use std::sync::{Arc, Mutex};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::io;
use std;
use config::CertChainConfig;
use std::thread;
use std::sync::mpsc::{channel, Sender};
use std::ops::DerefMut;
use std::io::{Read, Write, BufReader, BufWriter};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use blockchain::Block;
use rustc_serialize::{Encodable, Decodable};
use msgpack::{Encoder, Decoder};
use address::InstAddress;
use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::{Message};
use common::ValidityErr;
use key;
use std::fmt::{Display, Formatter};
use signature::RecovSignature;
use hash::DoubleSha256Hash;
use std::hash::{SipHasher, Hash};
use rand::os::OsRng;
use rand::Rng;

struct Socket {
    tcp_sock: Arc<Mutex<Option<TcpStream>>>,
}

#[derive(RustcEncodable, RustcDecodable, Debug)]
struct NetworkMessage {
    pub magic: u32,
    pub payload: NetPayload,
    pub payload_checksum: u32,
}

#[derive(RustcEncodable, RustcDecodable, Debug)]
pub enum NetPayload {
    IdentReq(IdentityRequest),
}

pub struct NetPeer {
    pub inst_addr: InstAddress,
    pub hostname: String,
    pub port: u16,
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
    pub from_hostname: String,
    pub from_port: u16,
    pub from_signature: RecovSignature,
}

#[derive(Debug)]
pub enum ConnectionState {
    NotConnected,
    ConnectedIdentityConfirmed,
    ConnectedIdentityUnconfirmed,
}

/*
 * TODO
 *  - Set up NetPeerTable
 *    - Seed with initial peers, have them connect at construction
 *      and ask for the identity from each.
 *    - fn issue_identresp(IdentityResponse) will look up an existing
 *      peer or create one if needed. Sending an identresp doesn't care if
 *      if peer's identity is not confirmed.
 *    - fn process_identresp(IdentityResponse) will look up the existing
 *      peer or drop the payload if it doesn't exist / identity was never
 *      requested in the first place; otherwise, set status to confirmed.
 *    - REMEMBER: The point is not to have full duplex, as we have no way
 *      of confirming whether an inbound socket maps to a hostname, nor
 *      should we, as messages are async and can be repeated. For inbound
 *      connections that have requested our identity but we never requested
 *      theirs, they will simply sit in the peer table, unverified, until/unless
 *      we have the need to connect and verify their identity.
 */

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

    pub fn connect(&mut self, hostname: &str, port: u16) -> std::io::Result<()> {
        match self.conn_state {
            ConnectionState::NotConnected => {
                info!("Connecting to peer {}...", self);
                match self.socket.connect(hostname, port) {
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

    pub fn request_identity(&mut self, from_peer: &NetPeer,
                            from_peer_sk: &SecretKey) -> std::io::Result<()> {
        match self.conn_state {
            ConnectionState::ConnectedIdentityUnconfirmed => {
                let identreq = IdentityRequest::new(&self,
                        &from_peer, &from_peer_sk);
                self.send(NetPayload::IdentReq(identreq.clone())).unwrap();
                self.identreq = Some(identreq);
                Ok(())
            },
            _ => Err(io::Error::new(io::ErrorKind::Other,
                    "Peer must be connected but unconfirmed to request identity."))
        }
    }

    pub fn send(&self, payload: NetPayload) -> std::io::Result<()> {
        match self.conn_state {
            ConnectionState::NotConnected =>
                Err(io::Error::new(io::ErrorKind::NotConnected,
                    "Unable to send payload to disconnected peer.")),
            ConnectionState::ConnectedIdentityUnconfirmed => {
                match payload {
                    NetPayload::IdentReq(_) => {
                        self.socket.send(NetworkMessage::new(payload))
                    },
                }
            },
            ConnectionState::ConnectedIdentityConfirmed =>
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
    pub fn new(to_peer: &NetPeer, from_peer: &NetPeer,
               from_peer_secret_key: &SecretKey) -> IdentityRequest {
        let mut crypto_rng = OsRng::new().unwrap();
        let nonce = crypto_rng.gen::<u64>();
        let from_inst_addr = from_peer.inst_addr;
        let from_hostname = String::from(&from_peer.hostname[..]);
        let from_port = from_peer.port;
        let to_hash = format!("{},{},{},{}", nonce, from_inst_addr,
                              from_hostname, from_port);
        IdentityRequest {
            nonce: nonce,
            to_inst_addr: to_peer.inst_addr,
            to_hostname: String::from(&to_peer.hostname[..]),
            to_port: to_peer.port,
            from_inst_addr: from_inst_addr,
            from_hostname: from_hostname,
            from_port: from_port,
            from_signature: RecovSignature::sign(
                &DoubleSha256Hash::hash(&to_hash.as_bytes()[..]),
                &from_peer_secret_key)
        }
    }

    pub fn check_validity(&self, inst_peer: &NetPeer) -> Result<(), ValidityErr> {
        if let Err(err) = self.to_inst_addr.check_validity() {
            return Err(ValidityErr::ToInstAddrInvalid);
        }
        if self.to_inst_addr != inst_peer.inst_addr {
            return Err(ValidityErr::ToInstAddrDoesntMatchOurs);
        }
        if self.to_hostname != inst_peer.hostname {
            return Err(ValidityErr::ToHostNameDoesntMatchOurs);
        }
        if self.to_port != inst_peer.port {
            return Err(ValidityErr::ToPortDoesntMatchOurs);
        }
        if let Err(err) = self.from_inst_addr.check_validity() {
            return Err(ValidityErr::FromInstAddrInvalid);
        }

        /*
         * Reconstruct the expected signature message and attempt to
         * recover the public key from the signature. If it succeeds *and*
         * the pubkey hashes to the sending institution address, we're good.
         */
        let from_combined = format!("{},{},{},{}", self.nonce, self.from_inst_addr,
                              self.from_hostname, self.from_port);
        let from_hash = &DoubleSha256Hash::hash(&from_combined.as_bytes()[..]);
        let from_pubkey_recov = match self.from_signature
                .recover_pubkey(&from_hash) {
            Ok(pubkey) => pubkey,
            Err(err) => return Err(ValidityErr::UnableToRecoverFromAddrPubkey),
        };
        let from_addr_recov = match InstAddress::from_pubkey(&from_pubkey_recov) {
            Ok(addr) => addr,
            Err(err) => return Err(ValidityErr::RecoveredFromAddrInvalid)
        };
        if self.from_inst_addr != from_addr_recov {
            return Err(ValidityErr::RecoveredFromAddrDoesntMatch)
        }
        return Ok(())
    }
}

impl NetworkMessage {
    pub fn new(payload: NetPayload) -> NetworkMessage {
        NetworkMessage {
            magic: 101,
            payload: payload,
            payload_checksum: 55, // TODO: Make this an actual checksum
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
                        net_msg.encode(&mut Encoder::new(&mut buf_writer));
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
                                    payload_tx_clone2.send(net_msg.payload);
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

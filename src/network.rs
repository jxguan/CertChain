use std::sync::{Arc, Mutex};
use std::net::{TcpListener, TcpStream};
use std::io;
use std::io::Result;
use config::CertChainConfig;
use std::thread;
use std::sync::mpsc::{channel, Sender};
use std::ops::DerefMut;
use std::io::{Read, Write, BufReader, BufWriter};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use transaction::{Transaction};
use blockchain::Block;
use rustc_serialize::{Encodable, Decodable};
use msgpack::{Encoder, Decoder};
use address::Address;
use secp256k1::key::{SecretKey, PublicKey};

const PEER_CONN_ATTEMPT_INTERVAL_IN_MS: u32 = 3000;

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

#[derive(RustcEncodable, RustcDecodable, Debug)]
pub struct IdentityRequest {
    pub requester_addr: Address,
    // TODO: Add: pub requester_pubkey: PublicKey,
    pub requester_hostname: String,
    pub requester_port: u16,
    // TODO: Add: pub requester_sig: Signature,
}

impl IdentityRequest {
    pub fn new() -> IdentityRequest {
        IdentityRequest {
            requester_addr: Address::blank(),
            requester_hostname: "placeholder".to_string(),
            requester_port: 1337,
        }
    }

    pub fn is_valid(&self) -> bool {
        return true;
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

    pub fn connect(&mut self, hostname: &str, port: u16) -> Result<()> {
        match TcpStream::connect((hostname, port)) {
            Ok(sock) => {
                self.tcp_sock = Arc::new(Mutex::new(Some(sock)));
                self.send(NetworkMessage::new(
                        NetPayload::IdentReq(IdentityRequest::new()))).unwrap();
                Ok(())
            },
            Err(err) => {
                self.tcp_sock = Arc::new(Mutex::new(None));
                Err(err)
            }
        }
    }

    pub fn send(&self, net_msg: NetworkMessage) -> Result<()> {
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

    pub fn receive(&self) -> Result<NetworkMessage> {
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
    let listener_port: &u16 = &config.listener_port;
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

pub fn connect_to_peers(config: &CertChainConfig) -> Vec<Sender<NetPayload>> {

    let mut peer_txs = Vec::new();
    for peer in &config.peers {
        let peer_name = String::from(&peer.name[..]);
        let peer_port = peer.port;
        let peer_hostname = String::from(&peer.hostname[..]);
        let (tx, rx) = channel();
        peer_txs.push(tx);
        thread::spawn(move || {
            loop {
                let mut sock = Socket::new();
                info!("Attempting to connect to peer {} at {}:{}...",
                      peer_name, peer_hostname, peer_port);
                match sock.connect(&peer_hostname[..], peer_port) {
                    Ok(_) => {
                        info!("Successfully connected to {}; waiting for messages...`", peer_name);
                        loop {
                            let net_payload = rx.recv().unwrap();
                            let net_msg = NetworkMessage::new(net_payload);
                            debug!("Forwarding net msg to socket: {:?}", net_msg);
                            match sock.send(net_msg) {
                                Ok(_) => debug!("Net msg sent successfully to peer."),
                                Err(err) => {
                                    warn!("Failed to send net msg to peer \
                                        due to {}; will periodically attempt reconnect.", err);
                                    break;
                                }
                            }
                        }
                    },
                    Err(_) => {
                        warn!("Unable to connect to {}; retrying in {} ms.",
                              peer_name, PEER_CONN_ATTEMPT_INTERVAL_IN_MS);
                        thread::sleep_ms(PEER_CONN_ATTEMPT_INTERVAL_IN_MS);
                        continue;
                    }
                }
            }
        });
    }
    peer_txs
}

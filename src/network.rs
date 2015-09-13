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
use secp256k1::key::{SecretKey, PublicKey};
use address;
use address::Address;
use keys;

const MAX_PEER_CONN_ATTEMPTS: u8 = 3;
const PEER_CONN_ATTEMPT_INTERVAL_IN_MS: u32 = 3000;
const TRUST_CMD: u8 = 1;

struct Socket {
    tcp_sock: Arc<Mutex<Option<TcpStream>>>,
}

// TODO: This should be private to network module eventually.
#[derive(Debug, Copy, Clone)]
pub struct NetworkMessage {
    pub magic: u32,
    pub cmd: u8,
    pub payload_len: u32,
    pub payload_checksum: u32,
    pub payload: Payload,
}

#[derive(Debug, Copy, Clone)]
pub enum Payload {
    Trust(TrustPayload),
}

#[derive(Debug, Copy, Clone)]
pub struct TrustPayload {
    pub trustee_addr: Address,
    pub truster_addr: Address,
    pub truster_pubkey: PublicKey,
}

impl NetworkMessage {
    pub fn new(payload: Payload) -> NetworkMessage {
        NetworkMessage {
            magic: 101,
            cmd: TRUST_CMD,
            payload_len: 44,
            payload_checksum: 55,
            payload: payload
        }
    }
}

impl TrustPayload {
    pub fn new(addr: Address, secret_key: SecretKey,
               public_key: PublicKey) -> Result<TrustPayload> {
        Ok(TrustPayload {
            trustee_addr: addr,
            truster_addr: address::from_pubkey(&public_key).unwrap(),
            truster_pubkey: public_key,
        })
    }
    pub fn deserialize<R: Read>(mut reader: R) -> Result<TrustPayload> {
        Ok(TrustPayload {
            trustee_addr: address::deserialize(&mut reader).unwrap(),
            truster_addr: address::deserialize(&mut reader).unwrap(),
            truster_pubkey: keys::deserialize_pubkey(&mut reader).unwrap()
        })
    }
    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<()> {
        self.trustee_addr.serialize(&mut writer);
        self.truster_addr.serialize(&mut writer);
        keys::serialize_pubkey(&self.truster_pubkey, &mut writer);
        Ok(())
    }
}

impl NetworkMessage {
    pub fn deserialize<R: Read>(mut reader: R) -> Result<NetworkMessage> {
        let magic = reader.read_u32::<BigEndian>().unwrap();
        let cmd = reader.read_u8().unwrap();
        let payload_len = reader.read_u32::<BigEndian>().unwrap();
        let payload_checksum = reader.read_u32::<BigEndian>().unwrap();
        let payload = match cmd {
            TRUST_CMD => {
                Payload::Trust(TrustPayload::deserialize(&mut reader).unwrap())
            },
            _ => panic!("Unsupported message type.")
        };
        Ok(NetworkMessage {
            magic: magic,
            cmd: cmd,
            payload_len: payload_len,
            payload_checksum: payload_checksum,
            payload: payload,
        })
    }
    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<()> {
        writer.write_u32::<BigEndian>(self.magic).unwrap();
        writer.write_u8(self.cmd).unwrap();
        writer.write_u32::<BigEndian>(self.payload_len).unwrap();
        writer.write_u32::<BigEndian>(self.payload_checksum).unwrap();
        match self.payload {
            Payload::Trust(ref payload) => payload.serialize(&mut writer).unwrap()
        }
        try!(writer.flush());
        Ok(())
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
                Ok(())
            },
            Err(err) => {
                self.tcp_sock = Arc::new(Mutex::new(None));
                Err(err)
            }
        }
    }

    pub fn send(&self, msg: NetworkMessage) -> Result<()> {
        match self.tcp_sock.lock() {
            Err(err) => {
                Err(io::Error::new(io::ErrorKind::NotConnected,
                                   "Socket mutex is poisoned."))
            },
            Ok(mut guard) => {
                match *guard.deref_mut() {
                    Some(ref mut tcp_stream) => {
                        info!("Writing out message to socket.");
                        msg.serialize(BufWriter::new(tcp_stream)).unwrap();
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

    pub fn receive(&self) -> Result<()> {
        match self.tcp_sock.lock() {
            Err(err) => {
                Err(io::Error::new(io::ErrorKind::NotConnected,
                                   "Socket mutex is poisoned."))
            },
            Ok(mut guard) => {
                match *guard.deref_mut() {
                    Some(ref mut tcp_stream) => {
                        match NetworkMessage::deserialize(
                                BufReader::new(tcp_stream)) {
                            Ok(msg) => info!("Received message from peer: {:?}", msg),
                            Err(err) => panic!("Received malformed msg: {}", err)
                        }
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
}

pub fn listen(config: &CertChainConfig) -> () {

    // Start listening on the listener port in the provided config.
    let listener_port: &u16 = &config.listener_port;
    let listener = match TcpListener::bind(
            (&"127.0.0.1"[..], *listener_port)) {
        Ok(listener) => {
            info!("Successfully established listener on port {}.",
                  listener_port);
            listener
        },
        Err(e) => panic!("Unable to listen on port {}: {}",
                         listener_port, e),
    };

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    thread::spawn(move || {
                        let recv_sock = Socket {
                            tcp_sock: Arc::new(Mutex::new(Some(stream))),
                        };
                        loop {
                            recv_sock.receive();
                        }
                    });
                },
                Err(e) => warn!("Ignoring client request due to error: {}", e)
            }
        }
    });
}

pub fn connect_to_peers(config: &CertChainConfig) -> Vec<Sender<NetworkMessage>> {
    let mut peer_txs = Vec::new();
    for peer in &config.peers {
        info!("Connecting to {}...", peer.name);
        let mut attempts = 1;
        loop {
            let mut sock = Socket::new();
            match sock.connect(&peer.hostname[..], peer.port) {
                Ok(_) => {
                    info!("Successfully connected to {}.", peer.name);
                    let (tx, rx) = channel();
                    thread::spawn(move || {
                        loop {
                            let msg = rx.recv().unwrap();
                            info!("Received MSPC message; forwarding to socket.");
                            sock.send(msg);
                        }
                    });
                    peer_txs.push(tx);
                    break
                },
                Err(e) => {
                    if attempts <= MAX_PEER_CONN_ATTEMPTS {
                        warn!("Attempt {} to connect to {} failed; retrying...",
                              attempts, peer.name);
                        thread::sleep_ms(PEER_CONN_ATTEMPT_INTERVAL_IN_MS);
                        attempts += 1;
                        continue;
                    } else {
                        warn!("Failed to connect to {}: {}", peer.name, e);
                        break;
                    }
                }
            }
        }
    }
    peer_txs
}

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
use secp256k1::{Secp256k1, Signature, Message, RecoveryId};
use address;
use address::Address;
use keys;
use network;

const MAX_PEER_CONN_ATTEMPTS: u8 = 3;
const PEER_CONN_ATTEMPT_INTERVAL_IN_MS: u32 = 3000;
const TRUST_CMD: u8 = 1;
const SIGNATURE_LEN_BYTES: usize = 70;

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
    pub signature: Signature,
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
        let truster_addr = address::from_pubkey(&public_key).unwrap();
        let checksum = Self::checksum(&addr, &truster_addr, &public_key);
        let secp256k1_msg = Message::from_slice(&checksum[..]).unwrap();
        let context = Secp256k1::new();
        let signature = context.sign(&secp256k1_msg, &secret_key).unwrap();
        let payload = TrustPayload {
            trustee_addr: addr,
            truster_addr: truster_addr,
            truster_pubkey: public_key,
            signature: signature,
        };
        assert!(payload.has_valid_signature());
        Ok(payload)
    }
    pub fn deserialize<R: Read>(mut reader: R) -> Result<TrustPayload> {
        let payload = TrustPayload {
            trustee_addr: address::deserialize(&mut reader).unwrap(),
            truster_addr: address::deserialize(&mut reader).unwrap(),
            truster_pubkey: keys::deserialize_pubkey(&mut reader).unwrap(),
            signature: network::deserialize_signature(&mut reader).unwrap(),
        };
        assert!(payload.has_valid_signature());
        Ok(payload)
    }
    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<()> {
        info!("Serialzing TrustPayload to writer...");
        self.trustee_addr.serialize(&mut writer);
        self.truster_addr.serialize(&mut writer);
        keys::serialize_pubkey(&self.truster_pubkey, &mut writer);
        self.serialize_signature(&mut writer);
        Ok(())
    }
    fn checksum(trustee_addr: &Address, truster_addr: &Address,
                truster_pubkey: &PublicKey) -> [u8; 32] {
        let mut data = Vec::new();
        trustee_addr.serialize(&mut data);
        truster_addr.serialize(&mut data);
        keys::serialize_pubkey(&truster_pubkey, &mut data);
        let checksum = address::double_sha256(&data[..]);
        checksum
    }
    pub fn has_valid_signature(&self) -> bool {
        let checksum = Self::checksum(&self.trustee_addr, &self.truster_addr, &self.truster_pubkey);
        info!("[SigValidity] checksum: {:?}", &checksum);
        let secp256k1_msg = Message::from_slice(&checksum[..]).unwrap();
        info!("[SigValidity] msg: {:?}", &secp256k1_msg);
        let context = Secp256k1::new();
        info!("[SigValidity] pubkey: {:?}", &self.truster_pubkey);
        match context.verify(&secp256k1_msg, &self.signature, &self.truster_pubkey) {
            Ok(_) => {
                info!("Signature is valid: {:?}", &self.signature);
                true
            }
            Err(e) => {
                error!("Signature is invalid {:?}; reason: {:?}", &self.signature, e);
                false
            }
        }
    }
    pub fn serialize_signature<W: Write>(&self, mut writer: W) -> Result<()> {
        info!("Serializing signature of length: {}", &self.signature.len());
        info!("Serialized sig_buf: {:?}", &self.signature[..]);
        assert_eq!(self.signature[..].len(), SIGNATURE_LEN_BYTES);
        writer.write(&self.signature[..]).unwrap();
        Ok(())
    }
}

pub fn deserialize_signature<R: Read>(mut reader: R) -> Result<Signature> {
    let mut sig_buf = [0u8; SIGNATURE_LEN_BYTES];
    reader.read(&mut sig_buf).unwrap();
    info!("Deserialized sig_buf: {:?}", &sig_buf[..]);
    let context = Secp256k1::new();
    let sig = Signature::from_slice(&sig_buf).unwrap();
    Ok(sig)
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

pub enum PeerNotice {
    Trust(Address, SecretKey, PublicKey),
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

    pub fn send(&self, notice: PeerNotice) -> Result<()> {
        let net_msg = match notice {
            PeerNotice::Trust(addr, secret_key, pub_key) => {
                let trust_payload = TrustPayload::new(
                    addr, secret_key, pub_key).unwrap();
                let net_msg = NetworkMessage::new(Payload::Trust(trust_payload));
                net_msg
            }
        };

        match self.tcp_sock.lock() {
            Err(err) => {
                Err(io::Error::new(io::ErrorKind::NotConnected,
                                   "Socket mutex is poisoned."))
            },
            Ok(mut guard) => {
                match *guard.deref_mut() {
                    Some(ref mut tcp_stream) => {
                        info!("Writing out message to socket.");
                        net_msg.serialize(BufWriter::new(tcp_stream)).unwrap();
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

pub fn connect_to_peers(config: &CertChainConfig) -> Vec<Sender<PeerNotice>> {
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

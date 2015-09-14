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
use key;
use network;

const MAX_PEER_CONN_ATTEMPTS: u8 = 3;
const PEER_CONN_ATTEMPT_INTERVAL_IN_MS: u32 = 3000;
const INV_CMD: u8 = 1;
const SIGNATURE_LEN_BYTES: usize = 70;
const TRUST_TXN_TYPE: u8 = 1;
const REVOKE_TRUST_TXN_TYPE: u8 = 2;
const CERTIFY_TXN_TYPE: u8 = 3;
const REVOKE_CERTIFICATION_TXN_TYPE: u8 = 4;

struct Socket {
    tcp_sock: Arc<Mutex<Option<TcpStream>>>,
}

// TODO: This should be private to network module eventually.
#[derive(Debug)]
pub struct NetworkMessage {
    pub magic: u32,
    pub cmd: u8,
    pub payload_len: u32,
    pub payload_checksum: u32,
    pub payload: Payload,
}

#[derive(Debug)]
pub enum Payload {
    Transaction(Transaction),
}

#[derive(Debug)]
pub enum TransactionType {
    Trust(Address),
    RevokeTrust(Address),
    Certify([u8; 32]),
    RevokeCertification([u8; 32]),
}

#[derive(Debug)]
pub struct Transaction {
    pub txn_type: TransactionType,
    pub author_addr: Address,
    pub author_pubkey: PublicKey,
    pub author_sig: Signature,
}

impl NetworkMessage {
    pub fn new(payload: Payload) -> NetworkMessage {
        NetworkMessage {
            magic: 101,
            cmd: INV_CMD,
            payload_len: 44,
            payload_checksum: 55,
            payload: payload
        }
    }
}

/**
 * TODO: During validity check, ensure that provided pubkey
 * hashes to the provided address.
 */
impl Transaction {

    pub fn new(txn_type: TransactionType,
               author_seckey: SecretKey,
               author_pubkey: PublicKey) -> Result<Transaction> {

        // Compute author's address from public key.
        let author_addr = address::from_pubkey(&author_pubkey).unwrap();

        // Compute and sign checksum.
        let checksum = Self::checksum(
                &txn_type, &author_addr, &author_pubkey);
        let checksum_msg = Message::from_slice(&checksum[..]).unwrap();
        let context = Secp256k1::new();
        let author_sig= context.sign(&checksum_msg, &author_seckey).unwrap();

        let txn = Transaction {
            txn_type: txn_type,
            author_addr: author_addr,
            author_pubkey: author_pubkey,
            author_sig: author_sig,
        };

        assert!(txn.has_valid_signature());
        Ok(txn)
    }

    pub fn deserialize<R: Read>(mut reader: R) -> Result<Transaction> {

        let txn_type = match reader.read_u8().unwrap() {
            TRUST_TXN_TYPE => {
                let addr = address::deserialize(&mut reader).unwrap();
                TransactionType::Trust(addr)
            },
            REVOKE_TRUST_TXN_TYPE => {
                let addr = address::deserialize(&mut reader).unwrap();
                TransactionType::RevokeTrust(addr)
            },
            CERTIFY_TXN_TYPE => {
                let mut doc_checksum_buf = [0u8; 32];
                reader.read(&mut doc_checksum_buf).unwrap();
                TransactionType::Certify(doc_checksum_buf)
            },
            REVOKE_CERTIFICATION_TXN_TYPE => {
                let mut certify_txn_id_buf = [0u8; 32];
                reader.read(&mut certify_txn_id_buf).unwrap();
                TransactionType::RevokeCertification(certify_txn_id_buf)
            },
            i => panic!("Attempted to deserialize unsupported txn_type\
                        magic: {}", i)
        };

        let txn = Transaction {
            txn_type: txn_type,
            author_addr: address::deserialize(&mut reader).unwrap(),
            author_pubkey: key::deserialize_pubkey(&mut reader).unwrap(),
            author_sig: network::deserialize_signature(&mut reader).unwrap(),
        };

        assert!(txn.has_valid_signature());
        Ok(txn)
    }

    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<()> {
        Self::serialize_txn_type(&self.txn_type, &mut writer);
        self.author_addr.serialize(&mut writer);
        key::serialize_pubkey(&self.author_pubkey, &mut writer);
        self.serialize_signature(&mut writer);
        Ok(())
    }

    fn checksum(txn_type: &TransactionType,
                author_addr: &Address,
                author_pubkey: &PublicKey) -> [u8; 32] {
        let mut buf = Vec::new();
        Self::serialize_txn_type(&txn_type, &mut buf);
        author_addr.serialize(&mut buf);
        key::serialize_pubkey(&author_pubkey, &mut buf);
        address::double_sha256(&buf[..])
    }

    pub fn has_valid_signature(&self) -> bool {
        let checksum = Self::checksum(&self.txn_type, &self.author_addr, &self.author_pubkey);
        info!("[SigValidity] checksum: {:?}", &checksum);
        let checksum_msg = Message::from_slice(&checksum[..]).unwrap();
        info!("[SigValidity] msg: {:?}", &checksum_msg);
        let context = Secp256k1::new();
        info!("[SigValidity] pubkey: {:?}", &self.author_pubkey);
        match context.verify(&checksum_msg, &self.author_sig, &self.author_pubkey) {
            Ok(_) => {
                info!("Signature is valid: {:?}", &self.author_sig);
                true
            }
            Err(e) => {
                error!("Signature is invalid {:?}; reason: {:?}", &self.author_sig, e);
                false
            }
        }
    }
    pub fn serialize_signature<W: Write>(&self, mut writer: W) -> Result<()> {
        info!("Serializing signature of length: {}", &self.author_sig.len());
        info!("Serialized sig_buf: {:?}", &self.author_sig[..]);
        assert_eq!(self.author_sig[..].len(), SIGNATURE_LEN_BYTES);
        writer.write(&self.author_sig[..]).unwrap();
        Ok(())
    }

    pub fn serialize_txn_type<W: Write>(txn_type: &TransactionType, mut writer: W) -> Result<()> {
        match *txn_type {
            TransactionType::Trust(addr) => {
                writer.write_u8(TRUST_TXN_TYPE).unwrap();
                addr.serialize(&mut writer);
            },
            TransactionType::RevokeTrust(addr) => {
                writer.write_u8(REVOKE_TRUST_TXN_TYPE).unwrap();
                addr.serialize(&mut writer);
            },
            TransactionType::Certify(doc_checksum) => {
                writer.write_u8(CERTIFY_TXN_TYPE).unwrap();
                writer.write(&doc_checksum[..]).unwrap();
            },
            TransactionType::RevokeCertification(txn_id) => {
                writer.write_u8(REVOKE_CERTIFICATION_TXN_TYPE).unwrap();
                writer.write(&txn_id[..]).unwrap();
            }
        };
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
            INV_CMD => {
                Payload::Transaction(Transaction::deserialize(&mut reader).unwrap())
            },
            n => panic!("Unsupported message type: {}", n)
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
            Payload::Transaction(ref txn) => txn.serialize(&mut writer).unwrap()
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

    pub fn send(&self, net_msg: NetworkMessage) -> Result<()> {
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

pub fn connect_to_peers(config: &CertChainConfig) -> Vec<Sender<TransactionType>> {

    let secret_key: SecretKey = key::secret_key_from_string(
            &config.secret_key).unwrap();
    let public_key: PublicKey = key::compressed_public_key_from_string(
            &config.compressed_public_key).unwrap();
    info!("Using public key: {:?}", &public_key);

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
                            let txn_type = rx.recv().unwrap();
                            info!("Received MSPC txn type, forwarding to socket: {:?}", txn_type);
                            let net_msg = match txn_type {
                                TransactionType::Trust(addr) => {
                                    let txn = Transaction::new(
                                        txn_type, secret_key.clone(), public_key.clone()).unwrap();
                                    NetworkMessage::new(Payload::Transaction(txn))
                                },
                                _ => panic!("Unsupported txn_type: {:?}", txn_type)
                            };
                            sock.send(net_msg);
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

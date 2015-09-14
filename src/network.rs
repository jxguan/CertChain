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
use key;
use transaction::{Transaction, TransactionType};

const INV_CMD: u8 = 1;
const MAX_PEER_CONN_ATTEMPTS: u8 = 3;
const PEER_CONN_ATTEMPT_INTERVAL_IN_MS: u32 = 3000;

struct Socket {
    tcp_sock: Arc<Mutex<Option<TcpStream>>>,
}

#[derive(Debug)]
struct NetworkMessage {
    pub magic: u32,
    pub cmd: u8,
    pub payload_len: u32,
    pub payload_checksum: u32,
    pub payload: Payload,
}

#[derive(Debug)]
enum Payload {
    Transaction(Transaction),
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
            Err(_) => {
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

    pub fn receive(&self, txn_pool_tx: Sender<Transaction>) -> Result<()> {
        match self.tcp_sock.lock() {
            Err(_) => {
                Err(io::Error::new(io::ErrorKind::NotConnected,
                                   "Socket mutex is poisoned."))
            },
            Ok(mut guard) => {
                match *guard.deref_mut() {
                    Some(ref mut tcp_stream) => {
                        match NetworkMessage::deserialize(
                                BufReader::new(tcp_stream)) {
                            Ok(msg) => {
                                info!("Received message from peer: {:?}", msg);
                                match msg.payload {
                                    Payload::Transaction(txn) =>
                                        txn_pool_tx.send(txn).unwrap()
                                }
                            }
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

pub fn listen(txn_pool_tx: Sender<Transaction>, config: &CertChainConfig) -> () {

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

    // TODO: Clean this up, no need to clone like this.
    let txn_pool_tx_c1 = txn_pool_tx.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let txn_pool_tx_c2 = txn_pool_tx_c1.clone();
                    thread::spawn(move || {
                        let recv_sock = Socket {
                            tcp_sock: Arc::new(Mutex::new(Some(stream))),
                        };
                        loop {
                            recv_sock.receive(txn_pool_tx_c2.clone()).unwrap();
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
                                TransactionType::Trust(_) => {
                                    let txn = Transaction::new(
                                        txn_type, secret_key.clone(), public_key.clone()).unwrap();
                                    NetworkMessage::new(Payload::Transaction(txn))
                                },
                                _ => panic!("Unsupported txn_type: {:?}", txn_type)
                            };
                            sock.send(net_msg).unwrap();
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

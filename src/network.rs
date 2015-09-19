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

const PAYLOAD_FLAG_TXN: u8 = 1;
const PAYLOAD_FLAG_BLOCK: u8 = 2;
const PEER_CONN_ATTEMPT_INTERVAL_IN_MS: u32 = 3000;

struct Socket {
    tcp_sock: Arc<Mutex<Option<TcpStream>>>,
}

#[derive(Debug)]
pub struct NetworkMessage {
    pub magic: u32,
    pub payload_flag: u8,
    pub payload_len: u32,
    pub payload_checksum: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum PayloadFlag {
    Transaction,
    Block
}

impl NetworkMessage {
    pub fn new(payload_type: PayloadFlag, payload: Vec<u8>) -> NetworkMessage {
        NetworkMessage {
            magic: 101,
            payload_flag: match payload_type {
                PayloadFlag::Transaction => PAYLOAD_FLAG_TXN,
                PayloadFlag::Block => PAYLOAD_FLAG_BLOCK,
            },
            payload_len: payload.len() as u32,
            payload_checksum: 55,
            payload: payload
        }
    }
}

impl NetworkMessage {
    pub fn deserialize<R: Read>(mut reader: R) -> Result<NetworkMessage> {
        let magic = try!(reader.read_u32::<BigEndian>());
        let payload_flag = try!(reader.read_u8());
        let payload_len = try!(reader.read_u32::<BigEndian>());
        let payload_checksum = try!(reader.read_u32::<BigEndian>());
        let mut payload = Vec::new();
        try!(reader.take(payload_len as u64).read_to_end(&mut payload));
        Ok(NetworkMessage {
            magic: magic,
            payload_flag: payload_flag,
            payload_len: payload_len,
            payload_checksum: payload_checksum,
            payload: payload,
        })
    }
    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<()> {
        try!(writer.write_u32::<BigEndian>(self.magic));
        try!(writer.write_u8(self.payload_flag));
        try!(writer.write_u32::<BigEndian>(self.payload_len));
        try!(writer.write_u32::<BigEndian>(self.payload_checksum));
        try!(writer.write(&self.payload[..]));
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
                        debug!("Writing out net msg to socket.");
                        try!(net_msg.serialize(BufWriter::new(tcp_stream)));
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
                        match NetworkMessage::deserialize(
                                BufReader::new(tcp_stream)) {
                            Ok(msg) => Ok(msg),
                            Err(err) => Err(io::Error::new(
                                    io::ErrorKind::NotConnected,
                                    format!("{}", err)))
                        }
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

pub fn listen(txn_pool_tx: Sender<Transaction>,
              block_tx: Sender<Block>,
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

    // TODO: Clean this up, no need to clone like this.
    let txn_pool_tx_c1 = txn_pool_tx.clone();
    let block_tx_c1 = block_tx.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    // TODO: Clean this up, no need to clone like this.
                    let txn_pool_tx_c2 = txn_pool_tx_c1.clone();
                    let block_tx_c2 = block_tx_c1.clone();
                    thread::spawn(move || {
                        let recv_sock = Socket {
                            tcp_sock: Arc::new(Mutex::new(Some(stream))),
                        };
                        loop {
                            match recv_sock.receive() {
                                Ok(msg) => {
                                    debug!("Received message from peer: {:?}", msg);
                                    match msg.payload_flag {
                                        PAYLOAD_FLAG_TXN => {
                                            let txn = Transaction::deserialize(&msg.payload[..]).unwrap();
                                            txn_pool_tx_c2.send(txn).unwrap();
                                        },
                                        PAYLOAD_FLAG_BLOCK => {
                                            let block = Block::deserialize(&msg.payload[..]).unwrap();
                                            block_tx_c2.send(block).unwrap();
                                        },
                                        n => panic!("Unsupported payload flag: {}.", n)
                                    };
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

pub fn connect_to_peers(config: &CertChainConfig) -> Vec<Sender<NetworkMessage>> {

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
                            let net_msg = rx.recv().unwrap();
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

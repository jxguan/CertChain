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

const MAX_PEER_CONN_ATTEMPTS: u8 = 3;
const PEER_CONN_ATTEMPT_INTERVAL_IN_MS: u32 = 3000;

struct Socket {
    tcp_sock: Arc<Mutex<Option<TcpStream>>>,
}

// TODO: This should be private to network module eventually.
#[derive(Debug)]
pub struct NetworkMessage {
    pub magic: u32,
    pub cmd: [u8; 12],
    pub payload_len: u32,
    pub payload_checksum: u32,
//    pub payload: Payload,
}

/*pub enum Payload {
    Trust(TrustPayload),
}*/

// TODO: Represent fields as abstracted structs (i.e., Address)
// rather than raw arrays.
/*pub struct TrustPayload {
    pub truster_addr: [u8; 20],
    pub trustee_addr: [u8; 20],
    pub truster_pubkey: [u8; 65],
}*/

impl NetworkMessage {
    pub fn deserialize<R: Read>(mut reader: R) -> Result<NetworkMessage> {
        let magic = reader.read_u32::<BigEndian>().unwrap();
        let mut cmd_buf = [0u8; 12];
        reader.read(&mut cmd_buf).unwrap();
        let payload_len = reader.read_u32::<BigEndian>().unwrap();
        let payload_checksum = reader.read_u32::<BigEndian>().unwrap();
        Ok(NetworkMessage {
            magic: magic,
            cmd: cmd_buf,
            payload_len: payload_len,
            payload_checksum: payload_checksum,
        })
    }
    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<()> {
        writer.write_u32::<BigEndian>(self.magic).unwrap();
        writer.write(&self.cmd[..]).unwrap();
        writer.write_u32::<BigEndian>(self.payload_len).unwrap();
        writer.write_u32::<BigEndian>(self.payload_checksum).unwrap();
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

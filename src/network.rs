use std::sync::{Arc, Mutex};
use std::net::{TcpListener, TcpStream};
use std::io;
use config::CertChainConfig;
use std::thread;
use std::sync::mpsc::{channel, Sender};
use std::ops::DerefMut;
use std::io::{Read, Write};

const MAX_PEER_CONN_ATTEMPTS: u8 = 3;
const PEER_CONN_ATTEMPT_INTERVAL_IN_MS: u32 = 3000;

#[derive(Debug)]
pub struct Message {
    pub placeholder: u8,
}

struct Socket {
    tcp_sock: Arc<Mutex<Option<TcpStream>>>,
}

impl Socket {

    pub fn new() -> Socket {
        Socket {
            tcp_sock: Arc::new(Mutex::new(None)),
        }
    }

    pub fn connect(&mut self, hostname: &str, port: u16)
            -> io::Result<()> {
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

    pub fn send(&self, msg: Message) -> io::Result<()> {
        match self.tcp_sock.lock() {
            Err(err) => {
                Err(io::Error::new(io::ErrorKind::NotConnected,
                                   "Socket mutex is poisoned."))
            },
            Ok(mut guard) => {
                match *guard.deref_mut() {
                    Some(ref mut tcp_stream) => {
                        info!("Writing out message to socket.");
                        let _ = tcp_stream.write(&[1u8,3u8,5u8,0u8]);
                        let _ = tcp_stream.flush();
                        info!("Sent placeholder bytes; TODO: send actual msg.");
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

    pub fn receive(&self) -> io::Result<()> {
        match self.tcp_sock.lock() {
            Err(err) => {
                Err(io::Error::new(io::ErrorKind::NotConnected,
                                   "Socket mutex is poisoned."))
            },
            Ok(mut guard) => {
                match *guard.deref_mut() {
                    Some(ref mut tcp_stream) => {
                        let mut buffer = [0u8; 10];
                        match tcp_stream.read(&mut buffer) {
                            Ok(0) => Err(io::Error::new(io::ErrorKind::NotConnected,
                                    "Received 0-length message; peer disconnected.")),
                            Ok(n) => {
                                let mut data_str = String::new();
                                for b in buffer.iter() {
                                    data_str = data_str + &format!("{:x}", b)[..];
                                }
                                info!("Received data of length {} on \
                                      listener socket: {}", n, data_str);
                                Ok(())
                            },
                            Err(err) => Err(err)
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

pub fn connect_to_peers(config: &CertChainConfig) -> Vec<Sender<Message>> {
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

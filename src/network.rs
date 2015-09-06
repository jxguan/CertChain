use std::sync::{Arc, Mutex};
use std::net::{TcpListener, TcpStream};
use std::io;
use config::CertChainConfig;
use std::thread;

const MAX_PEER_CONN_ATTEMPTS: u8 = 3;
const PEER_CONN_ATTEMPT_INTERVAL_IN_MS: u32 = 3000;

pub struct Socket {
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
}

fn handle_client(stream: TcpStream) {
    info!("TODO: Handle client.");
}

pub fn listen(config: CertChainConfig) -> () {

    // Start listening on the listener port in the provided config.
    let listener = match TcpListener::bind(
            (&"127.0.0.1"[..], config.listener_port)) {
        Ok(listener) => {
            info!("Successfully established listener on port {}.",
                  config.listener_port);
            listener
        },
        Err(e) => panic!("Unable to listen on port {}: {}",
                         config.listener_port, e),
    };

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    thread::spawn(move || {
                        handle_client(stream)
                    });
                },
                Err(e) => warn!("Ignoring client request due to error: {}", e)
            }
        }
    });

    // Connect to trusted peers.
    for peer in config.peers {
        info!("Connecting to {}...", peer.name);
        let mut attempts = 1;
        loop {
            let mut sock = Socket::new();
            match sock.connect(&peer.hostname[..], peer.port) {
                Ok(_) => {
                    info!("Successfully connected to {}.", peer.name);
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
}

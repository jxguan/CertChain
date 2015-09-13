extern crate log4rs;
extern crate getopts;
extern crate hyper;
extern crate rustc_serialize;
extern crate crypto;
extern crate toml;
extern crate byteorder;
extern crate secp256k1;
extern crate rand;
extern crate rust_base58;

#[macro_use]
extern crate log;

pub mod address;
pub mod daemon;
pub mod config;
pub mod network;
pub mod blockchain;
pub mod keys;

use std::thread;
use std::default::Default;

fn main() {

    // Using log4rs as the concrete logging implementation.
    log4rs::init_file("log.toml", Default::default()).unwrap();

    // Load configuration settings from file.
    let config = match config::load() {
        Ok(c) => c,
        Err(err) => panic!("Unable to load config file: {:?}", err)
    };

    // Kick off the main daemon thread.
    info!("Config loaded; spawning daemon thread.");
    let daemon_thread = thread::spawn(move || {
        daemon::run(config);
    });

    info!("Daemon thread spawned.");

    // Join on the daemon thread, otherwise it will be terminated
    // prematurely when main finishes.
    let _ = daemon_thread.join();
}

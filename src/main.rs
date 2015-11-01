#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

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
extern crate time;
extern crate rmp_serialize as msgpack;
extern crate compress;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate log;

pub mod common;
pub mod address;
pub mod daemon;
pub mod config;
pub mod network;
pub mod blockchain;
pub mod key;
pub mod hash;
pub mod signature;
pub mod fsm;
pub mod rpc;
pub mod hashchain;

use std::thread;
use std::default::Default;

fn main() {

    // Load configuration settings from file.
    let config = match config::load() {
        Ok(c) => c,
        Err(err) => panic!("Unable to load config file: {:?}", err)
    };

    // Using log4rs as the concrete logging implementation.
    log4rs::init_file(&config.log_config_filename,
                      Default::default()).unwrap();

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

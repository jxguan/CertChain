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

pub mod daemon;
pub mod config;
pub mod network;
pub mod blockchain;
pub mod keys;

use std::thread;
use std::default::Default;
use secp256k1::key::{SecretKey, PublicKey};

fn main() {

    // Using log4rs as the concrete logging implementation.
    log4rs::init_file("log.toml", Default::default()).unwrap();

    // Load configuration settings from file.
    let config = match config::load() {
        Ok(c) => c,
        Err(err) => panic!("Unable to load config file: {:?}", err)
    };

    /* BEGIN TEMPORARY */
    let sec_key: SecretKey = keys::secret_key_from_string(&config.secret_key).unwrap();
    let pub_key: PublicKey = keys::compressed_public_key_from_string(
            &config.compressed_public_key).unwrap();
    /* END TEMPORARY */

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

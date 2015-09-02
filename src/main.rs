extern crate certchain;
extern crate log4rs;

use std::thread;
use std::default::Default;

fn main() {

    // Using log4rs as the concrete logging implementation.
    log4rs::init_file("log.toml", Default::default()).unwrap();

    // Load configuration settings from file.
    let config = match certchain::config::load() {
        Ok(c) => c,
        Err(err) => panic!("Unable to load config file: {:?}", err)
    };

    // Kick off the main daemon thread.
    thread::spawn(move || {
        certchain::daemon::start(config);
    });

    // TODO: Kick of RPC server in separate thread here.
}

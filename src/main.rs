extern crate certchain;
extern crate log4rs;

#[macro_use]
extern crate log;

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
    info!("Config loaded; spawning daemon thread.");
    let daemon_thread = thread::spawn(move || {
        certchain::daemon::start(config);
    });

    info!("Daemon thread spawned.");
    info!("TODO: Kick off RPC server in separate thread here.");

    // Join on the daemon thread, otherwise it will be terminated
    // prematurely when main finishes.
    let _ = daemon_thread.join();
}

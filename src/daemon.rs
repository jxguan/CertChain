extern crate log;

pub fn start() -> () {
    info!("Starting CertChain daemon.");
    /*
     * Connect to network of peers.
     */
    listen();
}

pub fn listen() -> () {
    info!("Listening to network...");
}

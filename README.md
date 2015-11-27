# CertChain [![Build Status](https://travis-ci.org/mquinn/CertChain.svg)](https://travis-ci.org/mquinn/CertChain)
Peer-to-peer institutional document certification and revocation.

## Installation
* At this time, you must build from source. Before you can do so, you need to build the secp256k1 library from source as follows:
  * `$ git clone https://github.com/bitcoin/secp256k1.git`
  * Follow the steps in the README.md of the secp256k1 repository; when you get to the `./configure` line, use the following command instead: `$ ./configure --enable-module-ecdh --enable-module-recovery`. This enables the recoverable key module, which CertChain makes use of.
  * After running `sudo make install`, run `sudo ldconfig <path_to_secp256k1_libs>` to make CertChain aware of the secp256k1 libraries when compiling; note that by default, secp256k1 is installed to `/usr/local/lib` unless you specified otherwise.

## Developing
* To build CertChain, simply run `$ cargo build`.
* To run a node, run `$ cargo run -- -c <node_conf>`, where <node_conf> is a \*.conf file in the `/conf` subdirectory of this repository.
  * Typically, you'll want to run two or more instances of CertChain simultaneously. The files `nodeA.conf` and `nodeB.conf` can be used for a two node network. For a four node network, use `stanford.conf`, `virginia.conf`, `ireland.conf`, and `tokyo.conf`. (Note: the four node network is configured for EC2 and is not yet ready for local development again).
    * **Important**: Do not forget to add entries to your /etc/hosts file for any non-routeable hostnames used in the \*.conf files. For nodeA.conf, add `127.0.0.1 virginia`, for nodeB.conf, add `127.0.0.1 stanford`.
* As of this writing, the network and daemon modules in the `/src` subdirectory are changing often. The rest are utility modules that are more stable, and will be changed as additional supporting functions are needed.

## SJCL
* CertChain uses SJCL for client-side block verification. Use the following build string to build SJCL with the dependencies required by CertChain: `$ ./configure --without-all --with-sha256 --with-ripemd160 --with-codecHex`

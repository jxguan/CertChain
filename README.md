# CertChain [![Build Status](https://travis-ci.org/mquinn/CertChain.svg)](https://travis-ci.org/mquinn/CertChain)
Distributed cryptographic certification and revocation of academic records.

## Installation
* Download the latest nightly (not stable) Rust compiler. The latest compiler known to compile CertChain successfully is rustc 1.6.0-nightly (7499558dd 2015-11-28).
* `$ ./install.sh` to build the secp256k1 shared libraries required by CertChain at compilation and runtime.
* `$ cargo build` to build CertChain.

## Developing
* To build CertChain, simply run `$ cargo build`.
* To run a node, run `$ cargo run -- -c <node_conf>`, where <node_conf> is a \*.conf file in the `/conf` subdirectory of this repository.
  * Typically, you'll want to run two or more instances of CertChain simultaneously. The files `nodeA.conf` and `nodeB.conf` can be used for a two node network. For a four node network, use `stanford.conf`, `virginia.conf`, `ireland.conf`, and `tokyo.conf`. (Note: the four node network is configured for EC2 and is not yet ready for local development again).
    * **Important**: Do not forget to add entries to your /etc/hosts file for any non-routeable hostnames used in the \*.conf files. For nodeA.conf, add `127.0.0.1 virginia`, for nodeB.conf, add `127.0.0.1 stanford`.
* As of this writing, the network and daemon modules in the `/src` subdirectory are changing often. The rest are utility modules that are more stable, and will be changed as additional supporting functions are needed.

## SJCL
* CertChain uses SJCL for client-side block verification. Use the following build string to build SJCL with the dependencies required by CertChain: `$ ./configure --without-all --with-sha256 --with-ripemd160 --with-codecHex`

## Running a Demo
* If this is the first time you are running the demo, run ./init\_local\_nodes.sh
to configure the two local nodes.  You only need to go through this process
once.
* To run a demo, you might wany to run a local two-node network. To do this, you
can simply run $ ./start\_local\_nodes.sh, which will start two nodes in the
background with stanford on RPC port 5001, and virginia on RPC port 4001.
* The frontend uses Django. You will need a superuser to log in to the
administration system.  To do this, run $ ./admin/manage.py createsuperuser
--settings=admin.settings.stanford, and follow the instructions.
* Then, start the Django server by running $ ./admin/manage.py runserver
--settings=admin.settings.stanford
* Now you should be able to visit http://127.0.0.1:8000/, log in with the
account you just created.  Everything is there!
* After you are done, shutdown the server and run $ ./killall.sh to terminate
the two nodes.
* To reset the documents, hashchains, and replicas, run ./reset.py.

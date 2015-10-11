# CertChain [![Build Status](https://travis-ci.org/mquinn/CertChain.svg)](https://travis-ci.org/mquinn/CertChain)
Document certification with trust determined by democratic consensus.

## Development Notes
* The secp256k1 C++ library is both a build and runtime dependency; clone from GitHub and build from source via instructions in that repo's README. *You must enable the ECDH and recovery modules: `./configure --enable-module-ecdh --enable-module-recovery`*
* At runtime, the `LD_LIBRARY_PATH` environment variable must include the directory that contains the secp256k1 shared libraries; this will be `/usr/local/lib` if you ran `sudo make install` during secp256k1 compilation. You can also run `sudo ldconfig /usr/local/lib` instead of setting the environment variable directly.

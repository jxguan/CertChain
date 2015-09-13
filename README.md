# CertChain [![Build Status](https://travis-ci.org/mquinn/CertChain.svg)](https://travis-ci.org/mquinn/CertChain)
Document certification with trust determined by democratic consensus.

## Development Notes
* The secp256k1 C++ library is both a build and runtime dependency; clone from GitHub and build from source via instructions in that repo's README.
* IMPORTANT: As of this writing, must checkout commit 729badff148a00aebedce663e4ebb5a039170d9b, as HEAD is not properly wrapped by rust-secp256k1 (have not run git bisect to determine why this is the case).
* At runtime, the `LD_LIBRARY_PATH` environment variable must include the directory that contains the secp256k1 shared libraries; this will be `/usr/local/lib` if you ran `sudo make install` during secp256k1 compilation.

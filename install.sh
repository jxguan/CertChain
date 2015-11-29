#!/bin/bash

SECP256K1_SERVER_LIBS_PATH=$(readlink -f ./secp256k1_server_libs)
printf "Server-side secp256k1 libs will be installed to: %s\n" \
        $SECP256K1_SERVER_LIBS_PATH

# Ensure shared libs dir is gone.
rm -rf $SECP256K1_SERVER_LIBS_PATH

# Retrieve repositories.
git submodule init
git submodule update

# Build secp256k1 shared libs
# for server-side use.
cd secp256k1_server
./autogen.sh
./configure --prefix=$SECP256K1_SERVER_LIBS_PATH --enable-module-recovery
make clean
make
./tests
make install

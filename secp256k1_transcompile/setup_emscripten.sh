#!/bin/bash

rm -rf emsdk_portable
rm emsdk-portable.tar.gz

sudo apt-get update

# IMPORTANT: Emscripten also requires a JRE; if you don't have
# one on your system, be sure to add 'default-jre' to the install
# command below or acquire one through alternate means.
sudo apt-get install build-essential cmake python2.7 nodejs

wget https://s3.amazonaws.com/mozilla-games/emscripten/releases/emsdk-portable.tar.gz
tar xvf emsdk-portable.tar.gz
cd emsdk_portable
./emsdk update
./emsdk install latest
./emsdk activate latest

cd ..
rm emsdk-portable.tar.gz

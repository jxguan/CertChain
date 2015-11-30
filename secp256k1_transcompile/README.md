### Transcompiling secp256k1 to JS

CertChain depends on secp256k1 for client-side recoverable
signature verification; thus, it is necessary to cross-compile secp256k1
to JavaScript. Emscripten makes this possible, and thanks to
[this user's post](https://bitsharestalk.org/index.php/topic,17687.msg226056.html?PHPSESSID=60udjjt92b96na6ovp008j4vk2#msg226056) and his or her [related code](https://github.com/arhag/crypto-experiments/tree/emscripten/emscripten/libsecp256k1-demo), the configure script in this directory can be used to do the transcompilation.

The transcompiled JS file is versioned in this repo at `admin/public/static/public/js`, so you don't have to do the transcompilation from scratch if you are building CertChain (it's a lengthy process to install Emscripten due to its dependence on clang). However, if you want to change secp256k1 and see those changes reflected in the client-side code, you'll need to transcompile.

To do so, you will first need a local copy of Emscripten. I've written the `setup_emscripten.sh` script to automate this. Once Emscripten is installed, do the following:

* `$ cd <emsdk-dir>`
* `$ source ./emsdk-env.sh`
* `$ cd <this-directory>`
* `$ ./configure`
* `$ make`

After running `make`, the transcompiled JS file will be written to `admin/public/static/public/js/libsecp256k1.js`. You can change this in the `configure` script located in this directory.

function log(s) {
    console.log(s);
    var str;
    if (typeof s === 'object') {
        if (s.hasOwnProperty('message')) {
            str = s['message'];
        } else {
            str = JSON.stringify(s);
        }
    } else {
        str = s.toString();
    }
}

function go_sign(e)
{
    var msg_str = document.getElementById("msg").value;
    var sec_str = document.getElementById("sec").value;
    console.log('Go with msg="'+msg_str+'" and sec="'+sec_str+'"');

    var out = document.getElementById("out");
    out.innerText = "";

    if (msg_str == "" || sec_str == "")
    {
        log("Error: You must fill in both fields!");
        return;
    }

    var state = {};
    state.message = CryptoJS.enc.u8array.stringify(CryptoJS.SHA256(msg_str)); 
    state.secret_key = CryptoJS.enc.u8array.stringify(CryptoJS.SHA256(sec_str));
    Promise.resolve()
    .then(function(ret) {
        log("Generated seckey from string: " + sec_str);
        // Second argument to all API functions maps the expected argument name to the alias name
        // under which the expected argument can be found in object passed as the first argument.
        return secp256k1.api.point(state, {seckey: 'secret_key'});
    }).then(function(ret) {
        state.public_key = ret;
        log("Public key is: " + CryptoJS.enc.u8array.parse(state.public_key).toString());
        // The map can also be an Array. In which case, aliases for all expected arguments must be provided 
        // in the order defined by the API function.
        return secp256k1.api.ecdsa_sign(state, ['message', 'secret_key']);
    }).then(function(ret) {
        state.sig = ret.sig;
        state.recid = ret.recid;
        console.log(state.sig);
        log("Signature is: " + CryptoJS.enc.u8array.parse(state.sig).toString());
        log("recid = " + state.recid);
        // If an expected argument name maps to the same name as an alias, there is no need to include it in the map.
        // For example, in this case sig and recid are stored under the same name in state as what the function expects,
        // and therefore the map argument only maps 'msg' to 'message'.
        return secp256k1.api.ecdsa_recover(state, {msg: 'message'});
    }).then(function(ret) {
        state.recovered_pubkey = ret;
        log("Recovered public key is: " + CryptoJS.enc.u8array.parse(state.recovered_pubkey).toString());
        for (var i = 0; i < state.public_key.length; ++i)
        {
            if (state.recovered_pubkey[i] !== state.public_key[i])
            {
                log("Signature is incorrect.");
                return;
            }
        }
        log("Signature is correct.");
    }).catch(function(error) {
        log("Error occured: ");
        log(error);
    });
}

// Enforces length of len
function hex_str_to_uint8array(hex_str, len) {
    if (hex_str.length != len) {
        throw 'Expected hex string of length: ' + len;
    }
    var ua = new Uint8Array(len / 2);
    for (var i = 0; i < (len / 2); i++) {
        hex = hex_str.substring(i*2, i*2 + 2);
        dec = parseInt(hex, 16);
        ua[i] = dec
    }
    return ua;
}

function recover_signature_pubkey(message, signature) {
    // We expect signature to be <recid>|<signature>;
    // break them apart now.
    recid = signature.substring(0,1);
    sig = signature.substring(2);

    var state = {};
    state.message = hex_str_to_uint8array(message, 64);
    state.sig = hex_str_to_uint8array(sig, 128);
    state.recid = parseInt(recid); 
    Promise.resolve().then(function(ret) {
        // If an expected argument name maps to the same name as an alias, there is no need to include it in the map.
        // For example, in this case sig and recid are stored under the same name in state as what the function expects,
        // and therefore the map argument only maps 'msg' to 'message'.
        return secp256k1.api.ecdsa_recover(state, {msg: 'message'});
    }).then(function(ret) {
        state.recovered_pubkey = ret;
        log("Recovered public key is: " + CryptoJS.enc.u8array.parse(state.recovered_pubkey).toString());
    }).catch(function(error) {
        log("Error occured: ");
        log(error);
    });
}

function double_sha256(str) {
    var bitArray = sjcl.hash.sha256.hash(str);
    var digest_sha256 = sjcl.codec.hex.fromBits(bitArray); 
    bitArray = sjcl.hash.sha256.hash(digest_sha256);
    digest_sha256 = sjcl.codec.hex.fromBits(bitArray);
    return digest_sha256;
};

$(document).ready(function() {
  secp256k1.init().then(function() {
      console.log('Loaded secp256k1.');
      var json = $.parseJSON($('#raw-data').text());
      
      // TODO: Verify timestamp on block first.
      var block_header = json['most_recent_block_header'];

      // Compute hash of block header.
      var to_hash = 'BLOCKHEADER:'
        + block_header['timestamp']
        + ',' + block_header['parent']
        + ',' + block_header['author']
        + ',' + block_header['merkle_root']
        + ',' + block_header['signoff_peers_hash'];
      var computed_block_header_hash = double_sha256(to_hash);
      console.log('Computed block header hash: ' + computed_block_header_hash);
  
      // Recover the author's signature of the computed block
      // header hash: does the recovered public key
      // hash to the block's authoring address?
      recover_signature_pubkey(computed_block_header_hash,
        json['author_signature']);
  });
});
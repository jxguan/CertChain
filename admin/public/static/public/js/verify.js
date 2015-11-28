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

function recover_sig_inst_addr(message, signature) {
    // We expect signature to be <recid>|<signature>;
    // break them apart now.
    recid = signature.substring(0,1);
    sig = signature.substring(2);

    var state = {};
    state.message = hex_str_to_uint8array(message, 64);
    state.sig = hex_str_to_uint8array(sig, 128);
    state.recid = parseInt(recid);

    return Promise.resolve().then(function(ret) {
        // If an expected argument name maps to the same name as an alias, there is no need to include it in the map.
        // For example, in this case sig and recid are stored under the same name in state as what the function expects,
        // and therefore the map argument only maps 'msg' to 'message'.
        return secp256k1.api.ecdsa_recover(state, {msg: 'message'});
    }).then(function(ret) {
        state.recovered_pubkey = ret;
        var recov_pubkey_hex = CryptoJS.enc.u8array.parse(state.recovered_pubkey).toString();
        log("Recovered public key is: " + recov_pubkey_hex);
        var recov_inst_addr = pubkey_to_inst_address(recov_pubkey_hex);
        log("Recovered inst addr is: " + recov_inst_addr);
        return recov_inst_addr;
    }).catch(function(error) {
        log("Error occured: " + error);
        log(error);
    });
};

// Expects big endian words.
function word_array_to_uint8arr(word_arr) {
    var uint8arr = new Uint8Array(4 * word_arr.length);
    for (var i = 0; i < word_arr.length; i++) {
        var word = word_arr[i];
        uint8arr[4*i] = word >>> 24;
        uint8arr[4*i+1] = (word >>> 16) & 0x000000FF;
        uint8arr[4*i+2] = (word >>> 8) & 0x000000FF;
        uint8arr[4*i+3] = word & 0x000000FF; 
    }
    return uint8arr;
}

function pubkey_to_inst_address(pubkey_hex) {
    var inst_addr = new Uint8Array(25);

    // First byte is mainnet version prefix.
    inst_addr[0] = 88;

    // Next 20 bytes are RIPEMD160(SHA256(pubkey_hex))
    var bitArray = sjcl.hash.sha256.hash(pubkey_hex);
    var digest_sha256 = sjcl.codec.hex.fromBits(bitArray);
    // console.log(digest_sha256);
    wordArr = sjcl.hash.ripemd160.hash(digest_sha256);
    var uint8arr = word_array_to_uint8arr(wordArr);
    for (var i = 0; i < uint8arr.length; i++) {
        inst_addr[i+1] = uint8arr[i];
    }

    // Final 4 bytes are SHA256(SHA256(prev 21 bytes)).
    var to_checksum = CryptoJS.enc.u8array.parse(inst_addr.slice(0,21)).toString();
    // console.log('To checksum: ' + to_checksum);
    bitArray = sjcl.hash.sha256.hash(to_checksum);
    digest_sha256 = sjcl.codec.hex.fromBits(bitArray); 
    bitArray = sjcl.hash.sha256.hash(digest_sha256);
    uint8arr = word_array_to_uint8arr(bitArray);
    for (var i = 0; i < 4; i++) {
        inst_addr[i+21] = uint8arr[i];
    }

    // Encode InstAddress in base 58.
    return base58.encode(inst_addr);
};

function double_sha256(str) {
    var bitArray = sjcl.hash.sha256.hash(str);
    var digest_sha256 = sjcl.codec.hex.fromBits(bitArray); 
    bitArray = sjcl.hash.sha256.hash(digest_sha256);
    digest_sha256 = sjcl.codec.hex.fromBits(bitArray);
    return digest_sha256;
};

var check_author_sig = function(json, block_header_hash) {
    // Recover the author's signature of the computed block
    // header hash: does the recovered public key
    // hash to the block's authoring address?
    var block_header = json['most_recent_block_header'];
    recover_sig_inst_addr(block_header_hash,
    json['author_signature']).then(function(inst_addr) {
        if (inst_addr == block_header['author']) {
            $('#author-sig-valid').addClass('confirmed');
        } else {
            $('#author-sig-valid').addClass('invalid');
        }
        check_peer_sigs(json, block_header_hash);
    });
};

var check_peer_sigs = function(json, block_header_hash) {
    // Is there at least one other peer signatory?
    var peer_str = '|';
    var num_peers = 0;
    $.each(json['peer_signatures'], function(k, v) {
        num_peers++;
        peer_str += k + '|'
    });
    var block_header = json['most_recent_block_header'];
    var peer_str_hash = double_sha256(peer_str);
    if (num_peers > 0
            && peer_str_hash == block_header['signoff_peers_hash']) {
        $('#peer-hash-valid').addClass('confirmed');
    } else {
        $('#peer-hash-valid').addClass('invalid');
    }

    // Have all peers (of which there must be >= 1)
    // signed the block header?
    var map = {};
    if (num_peers > 0) {
        $.each(json['peer_signatures'], function(k, v) {
            /*
             * TODO: If you are here because you have multiple
             * peers and are getting a simultaneous use error
             * for secp256k1, you will need to chain the calls
             * to happen one after the other here.
             */
            recover_sig_inst_addr(block_header_hash,
                v).then(function(inst_addr) {
                    map[k] = (inst_addr == k);

                    // If we now have T/F results for all
                    // peer sigs, make sure are all valid.
                    if (map.length == json['peer_signatures'].length) {
                        var areAnyInvalid = false;
                        $.each(map, function(k, v) {
                            if (!v) {
                                areAnyInvalid = true;
                                return false;
                            }
                        });
                        if (!areAnyInvalid) {
                            $('#all-peers-signed').addClass('confirmed');
                        } else {
                            $('#all-peers-signed').addClass('invalid');
                        }
                    }
                }
            );
        });
    } else {
        $('#all-peers-signed').addClass('invalid');
    }
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

        check_author_sig(json, computed_block_header_hash);
    });
});
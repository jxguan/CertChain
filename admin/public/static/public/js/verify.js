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
            mark_checklist('author-sig-valid', true, json);
        } else {
            mark_checklist('author-sig-valid', false, json);
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
        mark_checklist('peer-hash-valid', true, json);
    } else {
        mark_checklist('peer-hash-valid', false, json);
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
                            mark_checklist('all-peers-signed', true, json);
                        } else {
                            mark_checklist('all-peers-signed', false, json);
                        }
                    }
                }
            );
        });
    } else {
        $('#all-peers-signed').addClass('invalid');
    }
};

var run_merkle_proof = function(json) {
    var node = json['merkle_node'];
    var node_str = node.document_id + '|'
        + node.certified_ts + '|'
        + node.certified_block_height;
    if (node.revoked_ts != null
        && node.revoked_block_height != null) {
        node_str += '|' + node.revoked_ts
            + '|' + node.revoked_block_height;
    }
    var node_hash = double_sha256(node_str);
    console.log('Node hash: ' + node_hash);

    // Apply each branch of the proof.
    var computed_root_hash = node_hash;
    $.each(json['merkle_proof']['branches'], function(idx, branch) {
        var pos = branch['position'];
        var branch_hash = branch['hash'];
        if (pos == 'L') {
            computed_root_hash = double_sha256(
                branch_hash + computed_root_hash);
        } else if (pos == 'R') {
            computed_root_hash = double_sha256(
                computed_root_hash + branch_hash);
        } else {
            throw 'Unexpected proof branch pos: ' + pos;
        }
    });

    var block_header = json['most_recent_block_header'];
    if (computed_root_hash == block_header['merkle_root']) {
        mark_checklist('merkle-proof-valid', true, json);
    } else {
        mark_checklist('merkle-proof-valid', false, json);
    }
};

var mark_checklist = function(dom_id, result, json) {
    if (checklist[dom_id] !== undefined) {
        if (result) {
            $('#' + dom_id).addClass('confirmed');
        } else {
            $('#' + dom_id).addClass('invalid');
        }
        checklist[dom_id] = result;

        // Is this the final pending item in the checklist?
        // If so, transform the status area accordingly.
        var all_items_done = true;
        var aggregate_result = true;
        $.each(checklist, function(item, item_status) {
            if (item_status == null) {
                all_items_done = false;
                return false;
            } else {
                aggregate_result = aggregate_result && item_status;
            }
        });
        if (all_items_done) {
            if (aggregate_result) {
                $('#verify-area').removeClass('gray').addClass('green');
                $('#progress-status').hide();
                $('#checklist').hide();
                var cert_ts = new Date(0);
                cert_ts.setUTCSeconds(json['merkle_node']['certified_ts']);
                var author_addr = json['most_recent_block_header']['author'];
                var author_hostname_port = json['node_locations'][author_addr];
                var block_ts = new Date(0);
                block_ts.setUTCSeconds(json['most_recent_block_header']['timestamp']);
                var ago = (new Date() - block_ts) / 1000 / 60;
                if (ago < 1) {
                    ago = parseInt((new Date() - block_ts) / 1000);
                    $('#ago').text(ago + ' second' + (ago == 1 ? '' : 's') + ' ago');
                } else {
                    ago = parseInt(ago);
                    $('#ago').text(ago + ' minute' + (ago == 1 ? '' : 's') + ' ago');
                }

                $('.block-author-hostname').text(author_hostname_port.split(':')[0]);
                var peer_list = [];
                $.each(json['node_locations'], function(k, v) {
                    var hostname = v.split(':')[0];
                    if (k != author_addr) {
                        peer_list.push(hostname);
                    }
                });
                var list_str = 'peer';
                if (peer_list.length > 1) {
                    list_str += 's ';
                } else {
                    list_str += ' ';
                }
                for (var i = 0; i < peer_list.length; i++) {
                    if (i != 0 && i == peer_list.length - 1) {
                        list_str += 'and ';
                    }
                    list_str += '<strong>' + peer_list[i] + '</strong>';
                    if (i != peer_list.length - 1) {
                        if (peer_list.length > 2) {
                            list_str += ', ';
                        } else {
                            list_str += ' ';
                        }
                    }
                }
                $('#peer-list').html(list_str);
                $('#cert-date').text(cert_ts);
                $('#valid-text').show();
            } else {
                $('#verify-area').removeClass('gray').addClass('red');
                $('#progress-status').hide();
                $('#invalid-text').show();
            }
        }
    } else {
        throw 'Received unexpected checklist DOM id: ' + dom_id;
    }
}

// null represents pending, true represents confirmed,
// false represents invalid.
var checklist = {
    'author-sig-valid': null,
    'peer-hash-valid': null,
    'all-peers-signed': null,
    'node-locs-agreed': null,
    'merkle-proof-valid': null,
    'within-last-hour': null
};
$(document).ready(function() {
    secp256k1.init().then(function() {
        console.log('Loaded secp256k1.');

        $('#verify-area').click(function(){
            $('#checklist').toggle();
        });

        $('#show-details').click(function(event){
            $('#peer-line, #raw-data-line, #hide-details').show();
            $('#show-details').hide();
            $('#verify-area').click(function(){
                $('#checklist').toggle();
            });
            event.stopPropagation();
        });

        $('#hide-details').click(function(event){
            $('#peer-line, #raw-data-line, #checklist, #hide-details').hide();
            $('#show-details').show();
            $('#verify-area').unbind('click');
            event.stopPropagation();
        });

        var json = $.parseJSON($('#raw-data').text());
        var block_header = json['most_recent_block_header'];

        // Compute hash of block header.
        var to_hash = 'BLOCKHEADER:'
        + block_header['timestamp']
        + ',' + block_header['parent']
        + ',' + block_header['author']
        + ',' + block_header['merkle_root']
        + ',' + block_header['signoff_peers_hash']
        + ',' + block_header['node_locations_hash'];
        var computed_block_header_hash = double_sha256(to_hash);
        console.log('Computed block header hash: ' + computed_block_header_hash);

        check_author_sig(json, computed_block_header_hash);
        run_merkle_proof(json);

        // Ensure node locations are reported correctly.
        var node_locs_str = '|';
        $.each(json['node_locations'], function(k, v) {
            node_locs_str += k + ':' + v + '|';
        });
        var node_locs_str_hash = double_sha256(node_locs_str);
        console.log(node_locs_str_hash);
        if (node_locs_str_hash
            == block_header['node_locations_hash']) {
            mark_checklist('node-locs-agreed', true, json);
        } else {
            mark_checklist('node-locs-agreed', false, json);
        }

        // Ensure block was authored within the last hour.
        var author_ts = new Date(0);
        var now = new Date();
        var ONE_HOUR_MILLIS = 60 * 60 * 1000;
        author_ts.setUTCSeconds(block_header['timestamp']);
        if (author_ts < now
                && (now - author_ts) < ONE_HOUR_MILLIS) {
            mark_checklist('within-last-hour', true, json);
        } else {
            mark_checklist('within-last-hour', false, json);
        }
    });
});
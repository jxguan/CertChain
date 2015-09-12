use secp256k1::key::{SecretKey, PublicKey};
use std::io::Result;
use rustc_serialize::hex::{FromHex, ToHex};
use secp256k1::Secp256k1;
use rand::os::OsRng;
use crypto::sha2::Sha256;
use crypto::ripemd160::Ripemd160;
use crypto::digest::Digest;
use rust_base58::base58::ToBase58;

const SECRET_KEY_LEN_BYTES: usize = 32;
const COMPRESSED_PUB_KEY_LEN_BYTES: usize = 33;
const MAINNET_ADDRESS_VERSION_PREFIX: u8 = 88; // "c" in Base58

pub fn secret_key_from_string(key_str: &String)
        -> Result<SecretKey> {
    let key_vec = key_str.to_string().from_hex().unwrap();
    assert!(key_vec.len() == SECRET_KEY_LEN_BYTES);
    let mut key_arr = [0u8; SECRET_KEY_LEN_BYTES];
    for i in 0..key_vec.len() {
        key_arr[i] = key_vec[i];
    }
    let context = Secp256k1::new();
    let sec_key = SecretKey::from_slice(&context, &key_arr[..]).unwrap();
    Ok(sec_key)
}

pub fn compressed_public_key_from_string(key_str: &String)
        -> Result<PublicKey> {
    let key_vec = key_str.to_string().from_hex().unwrap();
    assert!(key_vec.len() == COMPRESSED_PUB_KEY_LEN_BYTES);
    let mut key_arr = [0u8; COMPRESSED_PUB_KEY_LEN_BYTES];
    for i in 0..key_vec.len() {
        key_arr[i] = key_vec[i];
    }
    let context = Secp256k1::new();
    let pub_key = PublicKey::from_slice(&context, &key_arr[..]).unwrap();
    Ok(pub_key)
}

/*
 * NOTE: This is a helper function that doesn't
 * get called at runtime (institutions generate a keypair
 * only once, when they join the network). It's just easier to put
 * it here rather than make a new executable just
 * for this function.
 */
pub fn print_new_keypair() {
    let mut crypto_rng = OsRng::new().unwrap();
    let context = Secp256k1::new();
    let (priv_key, pub_key) = context.generate_keypair(&mut crypto_rng).unwrap();

    // Compress the public key.
    let compressed_pub_key = pub_key.serialize_vec(&context, true);

    // Generate the address from the public key.
    let mut sha256 = Sha256::new();
    let mut sha256_arr = [0u8; 32];
    sha256.input(&compressed_pub_key[..]);
    sha256.result(&mut sha256_arr);
    let mut ripemd160 = Ripemd160::new();
    let mut address_arr = [0u8; 25];
    // First byte is the version prefix.
    address_arr[0] = MAINNET_ADDRESS_VERSION_PREFIX;
    ripemd160.input(&sha256_arr[..]);
    // The next 20 bytes are the hash of the public key.
    ripemd160.result(&mut address_arr[1..21]);
    // The last 4 bytes are the checksum.
    checksum_address(&mut address_arr[..]);

    println!("Secret key: {:?}", priv_key);
    println!("Compressed public key: {}", &compressed_pub_key[..].to_hex());
    println!("Address: {:?}", &address_arr[..].to_base58());
}

pub fn checksum_address(addr: &mut [u8]) {
    let mut sha256 = Sha256::new();
    let mut sha256_arr = [0u8; 32];
    sha256.input(&addr[0..21]);
    sha256.result(&mut sha256_arr);
    sha256.reset();
    sha256.input(&sha256_arr[..]);
    sha256.result(&mut sha256_arr);
    addr[21] = sha256_arr[0];
    addr[22] = sha256_arr[1];
    addr[23] = sha256_arr[2];
    addr[24] = sha256_arr[3];
}

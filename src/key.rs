use secp256k1::key::{SecretKey, PublicKey};
use std::io::{Result};
use rustc_serialize::hex::{ToHex, FromHex};
use secp256k1::Secp256k1;
use rand::os::OsRng;
use address::InstAddress;

const SECRET_KEY_LEN_BYTES: usize = 32;
const COMPRESSED_PUB_KEY_LEN_BYTES: usize = 33;

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

pub fn print_new_keypair() {

    let mut crypto_rng = OsRng::new().unwrap();
    let context = Secp256k1::new();

    // A compressed public key is generated here using
    // the true argument to generate_keypair().
    let (priv_key, pub_key) = context.generate_keypair(
        &mut crypto_rng).unwrap();

    // Generate the address from public key.
    let address = InstAddress::from_pubkey(&pub_key).unwrap();

    println!("Secret key: {:?}", priv_key);
    println!("Compressed public key: {}",
             &pub_key.serialize_vec(&context, true)[..].to_hex());
    println!("Institutional address: {}", address.to_base58());
}

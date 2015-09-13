use secp256k1::key::{SecretKey, PublicKey};
use std::io::{Result, Read, Write};
use rustc_serialize::hex::{FromHex, ToHex};
use secp256k1::Secp256k1;
use rand::os::OsRng;
use crypto::sha2::Sha256;
use crypto::ripemd160::Ripemd160;
use crypto::digest::Digest;
use rust_base58::base58::ToBase58;
use address;

const SECRET_KEY_LEN_BYTES: usize = 32;
const COMPRESSED_PUB_KEY_LEN_BYTES: usize = 33;

pub fn deserialize_pubkey<R: Read>(mut reader: R) -> Result<PublicKey> {
    let mut key_buf = [0u8; COMPRESSED_PUB_KEY_LEN_BYTES];
    reader.read(&mut key_buf).unwrap();
    let context = Secp256k1::new();
    let pub_key = PublicKey::from_slice(&context, &key_buf[..]).unwrap();
    Ok(pub_key)
}

pub fn serialize_pubkey<W: Write>(pubkey: &PublicKey, mut writer: W) -> Result<()> {
    let context = Secp256k1::new();
    let compressed_pubkey = pubkey.serialize_vec(&context, true);
    assert_eq!(compressed_pubkey.len(), COMPRESSED_PUB_KEY_LEN_BYTES);
    writer.write(&compressed_pubkey[..]).unwrap();
    Ok(())
}

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

    // Generate the address from public key.
    let address = address::from_pubkey(&pub_key).unwrap();

    // Serialize the public_key to its compressed form.
    let compressed_pubkey = pub_key.serialize_vec(&context, true);

    println!("Secret key: {:?}", priv_key);
    println!("Compressed public key: {}", &compressed_pubkey[..].to_hex());
    println!("Address: {}", address.to_base58());
}


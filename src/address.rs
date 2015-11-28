use std::io::{Write};
use crypto::ripemd160::Ripemd160;
use crypto::digest::Digest;
use rust_base58::base58::{FromBase58, ToBase58};
use secp256k1::Secp256k1;
use secp256k1::key::{PublicKey};
use crypto::sha2::Sha256;
use hash::DoubleSha256Hash;
use std::fmt::{Debug, Display, Formatter};
use rustc_serialize::{Encodable};
use common::ValidityErr;
use serde::ser;
use serde::de;
use rustc_serialize::hex::ToHex;

const ADDRESS_LEN_BYTES: usize = 25;
const MAINNET_ADDRESS_VERSION_PREFIX: u8 = 88; // "c" in Base58

#[derive(RustcEncodable, RustcDecodable, Copy, Clone,
         Hash, Eq, Ord, PartialOrd, PartialEq)]
pub struct InstAddress {
    data: [u8; ADDRESS_LEN_BYTES],
}

impl InstAddress {

    pub fn from_string(addr_str: &str) -> Result<InstAddress, ValidityErr> {
        let addr: Vec<u8> = addr_str.as_bytes()[..].from_base58().unwrap();
        let mut addr_arr = [0u8; ADDRESS_LEN_BYTES];
        for i in 0..addr.len() {
            addr_arr[i] = addr[i];
        }

        let addr = InstAddress {
            data: addr_arr
        };
        match addr.check_validity() {
            Ok(_) => Ok(addr),
            Err(err) => Err(err)
        }
    }

    pub fn to_base58(&self) -> String {
        self.data[..].to_base58()
    }

    pub fn check_validity(&self) -> Result<(), ValidityErr> {
        if self.data.len() != ADDRESS_LEN_BYTES {
            return Err(ValidityErr::InstAddressLength)
        }
        if self.data[0] != MAINNET_ADDRESS_VERSION_PREFIX {
            return Err(ValidityErr::InstAddressVersionPrefix)
        }

        // Compute checksum on version + hash,
        // ensure it matches last 4 addr bytes.
        let to_checksum = &self.data[0..21].to_hex();
        let checksum = DoubleSha256Hash::hash_string(&to_checksum);
        if &checksum[0..4] != &self.data[21..25] {
            return Err(ValidityErr::InstAddressChecksum)
        }

        Ok(())
    }

   pub fn from_pubkey(pub_key: &PublicKey) -> Result<InstAddress, ValidityErr> {

        // The first byte of an InstAddress is always
        // the network version prefix.
        let mut address_arr = [0u8; ADDRESS_LEN_BYTES];
        address_arr[0] = MAINNET_ADDRESS_VERSION_PREFIX;

        // Compute the SHA256 of the public key bytes.
        let context = Secp256k1::new();
        let mut sha256 = Sha256::new();
        let pubkey_bytes = &pub_key.serialize_vec(&context, true);
        sha256.input_str(&pubkey_bytes[..].to_hex());
        let pubkey_sha256_str = sha256.result_str();

        // The next 20 bytes of an InstAddress are the
        // RIPEMD160 of the above SHA256 hash.
        let mut ripemd160 = Ripemd160::new();
        ripemd160.input_str(&pubkey_sha256_str);
        ripemd160.result(&mut address_arr[1..21]);

        // The last 4 bytes of an InstAddress are the
        // first 4 bytes of the checksum of the version + pubkey hash.
        let to_checksum = &address_arr[0..21].to_hex();
        info!("To checksum: {}", to_checksum);
        let checksum = DoubleSha256Hash::hash_string(&to_checksum);
        address_arr[21] = checksum[0];
        address_arr[22] = checksum[1];
        address_arr[23] = checksum[2];
        address_arr[24] = checksum[3];
        info!("Address arr: {:?}", address_arr);

        let addr = InstAddress {
            data: address_arr
        };

        match addr.check_validity() {
            Ok(_) => Ok(addr),
            Err(err) => Err(err)
        }
    }
}

impl ser::Serialize for InstAddress {
    fn serialize<S: ser::Serializer>(&self, s: &mut S)
            -> Result<(), S::Error> {
        s.visit_str(&self.to_base58()[..])
    }
}

impl de::Deserialize for InstAddress {
    fn deserialize<D: de::Deserializer>(d: &mut D)
            -> Result<InstAddress, D::Error> {
        d.visit_str(InstAddressVisitor)
    }
}

struct InstAddressVisitor;

impl de::Visitor for InstAddressVisitor {
    type Value = InstAddress;

    fn visit_str<E: de::Error>(&mut self, value: &str) -> Result<InstAddress, E> {
        match InstAddress::from_string(value) {
            Ok(addr) => Ok(addr),
            Err(_) => Err(de::Error::syntax(&format!(
                        "The visited string {} could not be deserialized \
                         into an InstAddress.", value)[..]))
        }
    }
}

impl Display for InstAddress {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        try!(write!(f, "{}", self.to_base58()));
        Ok(())
    }
}

impl Debug for InstAddress {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        try!(write!(f, "{}", self.to_base58()));
        Ok(())
    }
}


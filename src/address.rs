use std::io::{Result, Read, Write};
use crypto::ripemd160::Ripemd160;
use crypto::digest::Digest;
use rust_base58::base58::{FromBase58, ToBase58};
use secp256k1::Secp256k1;
use secp256k1::key::{PublicKey};
use crypto::sha2::Sha256;
use hash::DoubleSha256Hash;
use std::fmt::{Display, Formatter};
use rustc_serialize::{Encodable, Decodable};
use msgpack::{Encoder, Decoder};

const ADDRESS_LEN_BYTES: usize = 25;
const MAINNET_ADDRESS_VERSION_PREFIX: u8 = 88; // "c" in Base58

#[derive(RustcEncodable, RustcDecodable, Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct Address {
    data: [u8; ADDRESS_LEN_BYTES],
}

impl Address {

    pub fn blank() -> Address {
        Address {
            data: [0u8; ADDRESS_LEN_BYTES]
        }
    }

    pub fn to_base58(&self) -> String {
        self.data[..].to_base58()
    }

    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<()> {
        try!(writer.write(&self.data[..]));
        Ok(())
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        try!(write!(f, "{}", self.to_base58()));
        Ok(())
    }
}

fn assert_valid_address(addr: &[u8]) {
    assert_eq!(addr.len(), ADDRESS_LEN_BYTES);
    assert_eq!(addr[0], MAINNET_ADDRESS_VERSION_PREFIX);

    // Compute checksum on version + hash,
    // ensure it matches last 4 addr bytes.
    let checksum = DoubleSha256Hash::hash(&addr[0..21]);
    assert_eq!(&checksum[0..4], &addr[21..25]);
}

pub fn deserialize<R: Read>(mut reader: R) -> Result<Address> {
    let mut addr_buf = [0u8; ADDRESS_LEN_BYTES];
    try!(reader.read(&mut addr_buf));
    assert_valid_address(&addr_buf[..]);
    Ok(Address {
        data: addr_buf
    })
}

pub fn from_string(addr_str: &str) -> Result<Address> {
    let addr: Vec<u8> = addr_str.as_bytes()[..].from_base58().unwrap();
    assert_valid_address(&addr[..]);

    let mut addr_arr = [0u8; ADDRESS_LEN_BYTES];
    for i in 0..addr.len() {
        addr_arr[i] = addr[i];
    }

    Ok(Address {
        data: addr_arr
    })
}

pub fn from_pubkey(pub_key: &PublicKey) -> Result<Address> {
    // Generate the address from the compressed public key.
    let context = Secp256k1::new();
    let mut sha256 = Sha256::new();
    let mut sha256_arr = [0u8; 32];
    sha256.input(&pub_key.serialize_vec(&context, true)[..]);
    sha256.result(&mut sha256_arr);
    let mut ripemd160 = Ripemd160::new();
    let mut address_arr = [0u8; ADDRESS_LEN_BYTES];
    // First byte is the version prefix.
    address_arr[0] = MAINNET_ADDRESS_VERSION_PREFIX;
    ripemd160.input(&sha256_arr[..]);
    // The next 20 bytes are the hash of the public key.
    ripemd160.result(&mut address_arr[1..21]);
    // The last 4 bytes are the checksum of the version + pubkey hash.
    let checksum = DoubleSha256Hash::hash(&address_arr[0..21]);
    // We append only the first 4 bytes of the checksum to the end of the address.
    address_arr[21] = checksum[0];
    address_arr[22] = checksum[1];
    address_arr[23] = checksum[2];
    address_arr[24] = checksum[3];

    assert_valid_address(&address_arr[..]);
    Ok(Address {
        data: address_arr
    })
}

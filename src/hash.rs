use crypto::sha2::Sha256;
use crypto::digest::Digest;
use std::ops::{Index, Range, RangeFull};
use std::fmt::{Debug, Display, Formatter};
use std::io::{Write};
use serde::{ser, de};
use common::ValidityErr;
use rustc_serialize::hex::FromHex;

#[derive(RustcEncodable, RustcDecodable, Copy, Clone, Hash,
         Eq, PartialEq, Ord, PartialOrd)]
pub struct DoubleSha256Hash([u8; 32]);

impl DoubleSha256Hash {
    pub fn blank() -> DoubleSha256Hash {
        DoubleSha256Hash([0u8; 32])
    }

    pub fn hash(data: &[u8]) -> DoubleSha256Hash {
        let DoubleSha256Hash(mut buf) = DoubleSha256Hash::blank();
        let mut sha256 = Sha256::new();
        sha256.input(data);
        sha256.result(&mut buf);
        sha256.reset();
        sha256.input(&buf);
        sha256.result(&mut buf);
        DoubleSha256Hash(buf)
    }

    /// You should use this function for any string hashes that must
    /// be reproduced in client-side JavaScript; using the other method
    /// that accepts a slice makes the client-side code needlessly complex.
    pub fn hash_string(string: &str) -> DoubleSha256Hash {
        let DoubleSha256Hash(mut buf) = DoubleSha256Hash::blank();
        let mut sha256 = Sha256::new();
        sha256.input_str(string);
        let string2 = sha256.result_str();
        sha256.reset();
        sha256.input_str(&string2);
        sha256.result(&mut buf);
        DoubleSha256Hash(buf)
    }

    pub fn from_string(hash_str: &str) -> Result<DoubleSha256Hash, ValidityErr> {
        let hash_vec = match hash_str.from_hex() {
            Ok(v) => v,
            Err(_) => return Err(ValidityErr::DoubleSha256HashExpected)
        };

        if hash_vec.len() != 32 {
            return Err(ValidityErr::DoubleSha256HashExpected);
        }

        let mut hash_arr = [0u8; 32];
        for i in 0..hash_vec.len() {
            hash_arr[i] = hash_vec[i];
        }

        Ok(DoubleSha256Hash(hash_arr))
    }

    pub fn from_slice(slice: &[u8]) -> DoubleSha256Hash {
        let DoubleSha256Hash(mut buf) = DoubleSha256Hash::blank();
        assert_eq!(slice.len(), buf.len());
        for i in 0..slice.len() {
            buf[i] = slice[i]
        }
        DoubleSha256Hash(buf)
    }

    pub fn genesis_block_parent_hash() -> DoubleSha256Hash {
        DoubleSha256Hash::from_slice(&[0u8; 32][..])
    }
}

impl Debug for DoubleSha256Hash {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        let &DoubleSha256Hash(data) = self;
        for b in data.iter() {
            try!(write!(f, "{:02x}", b));
        }
        Ok(())
    }
}

impl ser::Serialize for DoubleSha256Hash {
    fn serialize<S: ser::Serializer>(&self, s: &mut S)
        -> Result<(), S::Error> {
        s.visit_str(&format!("{}", self)[..])
    }
}

impl de::Deserialize for DoubleSha256Hash {
    fn deserialize<D: de::Deserializer>(d: &mut D)
            -> Result<DoubleSha256Hash, D::Error> {
        d.visit_str(DoubleSha256HashVisitor)
    }
}

struct DoubleSha256HashVisitor;

impl de::Visitor for DoubleSha256HashVisitor {
    type Value = DoubleSha256Hash;

    fn visit_str<E: de::Error>(&mut self, value: &str)
            -> Result<DoubleSha256Hash, E> {
        match DoubleSha256Hash::from_string(value) {
            Ok(hash) => Ok(hash),
            Err(_) => Err(de::Error::syntax(&format!(
                        "The visited string {} could not be deserialized \
                         into a DoubleSha256Hash.", value)[..]))
        }
    }
}

impl Display for DoubleSha256Hash {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        let &DoubleSha256Hash(data) = self;
        for b in data.iter() {
            try!(write!(f, "{:02x}", b));
        }
        Ok(())
    }
}

impl Index<usize> for DoubleSha256Hash {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        let &DoubleSha256Hash(ref data) = self;
        &data[index]
    }
}

impl Index<Range<usize>> for DoubleSha256Hash {
    type Output = [u8];
    fn index(&self, index: Range<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl Index<RangeFull> for DoubleSha256Hash {
    type Output = [u8];
    fn index(&self, _: RangeFull) -> &[u8] {
        &self.0[..]
    }
}

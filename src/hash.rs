use crypto::sha2::Sha256;
use crypto::digest::Digest;
use std::ops::{Index, Range, RangeFull};
use std::fmt::{Debug, Display, Formatter};
use std::io::{Write};
use serde::{ser, de};
use common::ValidityErr;
use rustc_serialize::hex::FromHex;

/*
 * Credit to Andrew Poelstra for the following implementations
 * in this file (from his rust-bitcoin project):
 * - DoubleSha256 struct, from_data method of impl
 * - MerkleRoot trait and implementation
 */

pub trait MerkleRoot {
    fn merkle_root(&self) -> DoubleSha256Hash;
}

/*impl<'a> MerkleRoot for &'a [Transaction] {
    fn merkle_root(&self) -> DoubleSha256Hash {
        fn merkle_root(data: Vec<DoubleSha256Hash>) -> DoubleSha256Hash {
            if data.len() == 0 {
                return DoubleSha256Hash::blank()
            }
            if data.len() == 1 {
                let DoubleSha256Hash(buf) = data[0];
                return DoubleSha256Hash(buf)
            }
            let mut next = vec![];
            for idx in 0..((data.len() + 1) / 2) {
                let idx1 = 2 * idx;
                let idx2 = cmp::min(idx1 + 1, data.len() - 1);
                let mut combined_bytes = Vec::new();
                data[idx1].serialize(&mut combined_bytes).unwrap();
                data[idx2].serialize(&mut combined_bytes).unwrap();
                next.push(DoubleSha256Hash::hash(&combined_bytes[..]));
            }
            merkle_root(next)
        }
        merkle_root(self.iter().map(|txn| {
            let mut txn_bytes = Vec::new();
            txn.serialize(&mut txn_bytes).unwrap();
            DoubleSha256Hash::hash(&txn_bytes[..])
        }).collect())
    }
}

impl MerkleRoot for Vec<Transaction> {
    fn merkle_root(&self) -> DoubleSha256Hash {
        (&self[..]).merkle_root()
    }
}*/

#[derive(RustcEncodable, RustcDecodable, Copy, Clone, Hash, Eq, PartialEq)]
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

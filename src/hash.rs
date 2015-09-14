use crypto::sha2::Sha256;
use crypto::digest::Digest;
use std::ops::{Index, Range, RangeFull};
use std::fmt::{Debug, Formatter};

/*
 * Credit to Andrew Poelstra for the following implementations
 * in this file (from his rust-bitcoin project):
 * - DoubleSha256 struct, from_data method of impl
 */

pub struct DoubleSha256Hash([u8; 32]);

impl DoubleSha256Hash {
    pub fn blank() -> DoubleSha256Hash {
        DoubleSha256Hash([0u8; 32])
    }

    pub fn from_data(data: &[u8]) -> DoubleSha256Hash {
        let DoubleSha256Hash(mut buf) = DoubleSha256Hash::blank();
        let mut sha256 = Sha256::new();
        sha256.input(data);
        sha256.result(&mut buf);
        sha256.reset();
        sha256.input(&buf);
        sha256.result(&mut buf);
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

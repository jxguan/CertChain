/*use rustc_serialize::{Encodable, Decodable};
use msgpack::{Encoder, Decoder};
use std::fmt::{Display, Formatter, Debug};

const MAX_SIGNATURE_LEN_BYTES: usize = 72;

#[derive(RustcEncodable, RustcDecodable)]
pub struct Signature {
    pub len: u8,
    pub data: [u8; MAX_SIGNATURE_LEN_BYTES],
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        try!(write!(f, "(TODO:Implement Display for Signature)"));
        Ok(())
    }
}*/

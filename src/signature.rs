use rustc_serialize::{Encodable, Decodable, Encoder, Decoder};
use std::fmt::{Formatter, Debug};
use secp256k1::{RecoverableSignature, Secp256k1, RecoveryId, Message};
use secp256k1::key::{SecretKey, PublicKey};
use common::ValidityErr;
use hash::DoubleSha256Hash;

#[derive(Clone)]
pub struct RecovSignature {
    ctx: Secp256k1,
    sig: RecoverableSignature,
}

impl RecovSignature {
    pub fn sign(hash: &DoubleSha256Hash, secret_key: &SecretKey) -> RecovSignature {
        let ctx = Secp256k1::new();
        let sig = ctx.sign_recoverable(&Message::from_slice(&hash[..]).unwrap(),
            &secret_key).unwrap();
        RecovSignature {
            ctx: ctx,
            sig: sig
        }
    }
    pub fn recover_pubkey(&self, hash: &DoubleSha256Hash)
            -> Result<PublicKey, ValidityErr> {
        let msg = match Message::from_slice(&hash[..]) {
            Ok(msg) => msg,
            Err(_) => return Err(ValidityErr::Secp256k1MessageInvalidErr)
        };
        match self.ctx.recover(&msg, &self.sig) {
            Ok(pubkey) => return Ok(pubkey),
            Err(_) => return Err(ValidityErr::Secp256k1PubkeyRecoveryErr)
        };
    }
}

impl Encodable for RecovSignature {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let (recid, bytes) = self.sig.serialize_compact(&self.ctx);
        let _ = recid.to_i32().encode(s);
        for b in bytes.iter() {
            let _ = b.encode(s);
        }
        Ok(())
    }
}

impl Decodable for RecovSignature {
    fn decode<D: Decoder>(d: &mut D) -> Result<RecovSignature, D::Error> {
        let ctx = Secp256k1::new();
        let recid = RecoveryId::from_i32(try!(<i32>::decode(d))).unwrap();
        let mut bytes = [0u8; 64];
        for i in 0..bytes.len() {
            bytes[i] = try!(<u8>::decode(d));
        }
        let sig = RecoverableSignature::from_compact(&ctx, &bytes, recid).unwrap();
        Ok(RecovSignature {
            ctx: ctx,
            sig: sig,
        })
    }
}

impl Debug for RecovSignature {
    fn fmt(&self, f: &mut Formatter) -> ::std::fmt::Result {
        try!(write!(f, "{:?}", self.sig));
        Ok(())
    }
}

use rustc_serialize::{Encodable, Decodable, Encoder, Decoder};
use std::fmt::{Formatter, Debug};
use secp256k1::{RecoverableSignature, Secp256k1, RecoveryId, Message};
use secp256k1::key::{SecretKey, PublicKey};
use common::ValidityErr;
use hash::DoubleSha256Hash;
use address::InstAddress;

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

    pub fn check_validity(&self, expected_msg: &DoubleSha256Hash,
            expected_from_inst_addr: &InstAddress) -> Result<(), ValidityErr> {
        /*
         * Hash the expected signature message and attempt to
         * recover the public key from the signature. If it succeeds *and*
         * the pubkey hashes to the sending institution address, we're good.
         */
        let from_pubkey_recov = match self.recover_pubkey(&expected_msg) {
            Ok(pubkey) => pubkey,
            Err(_) => return Err(ValidityErr::UnableToRecoverFromAddrPubkey),
        };
        let from_addr_recov = match InstAddress::from_pubkey(&from_pubkey_recov) {
            Ok(addr) => addr,
            Err(_) => return Err(ValidityErr::RecoveredFromAddrInvalid)
        };
        if *expected_from_inst_addr != from_addr_recov {
            return Err(ValidityErr::RecoveredFromAddrDoesntMatch)
        }
        return Ok(())

    }

    fn recover_pubkey(&self, hash: &DoubleSha256Hash)
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
    // TODO: This should use the emit_struct, et al methods so that
    // this can be compatible with both MessagePack for net serialization
    // *and* JSON for RPC HTTP responses.
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        let (recid, bytes) = self.sig.serialize_compact(&self.ctx);
        try!(recid.to_i32().encode(s));
        for b in bytes.iter() {
            try!(b.encode(s));
        }
        Ok(())
    }
}

impl Decodable for RecovSignature {
    // TODO: See note above for Encodable impl.
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

use std::io::Result;
use std::io::{Read, Write};
use byteorder::{ReadBytesExt, WriteBytesExt};
use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::{Secp256k1, Signature, Message};
use address;
use address::Address;
use key;
use transaction;
use hash::DoubleSha256Hash;

const MAX_SIGNATURE_LEN_BYTES: usize = 72;
const TRUST_TXN_TYPE: u8 = 1;
const REVOKE_TRUST_TXN_TYPE: u8 = 2;
const CERTIFY_TXN_TYPE: u8 = 3;
const REVOKE_CERTIFICATION_TXN_TYPE: u8 = 4;

pub type TxnId = DoubleSha256Hash;

#[derive(Debug)]
pub enum TransactionType {
    Trust(Address),
    RevokeTrust(Address),
    Certify(DoubleSha256Hash),
    RevokeCertification(TxnId),
}

#[derive(Debug)]
pub struct Transaction {
    pub txn_type: TransactionType,
    pub author_addr: Address,
    pub author_pubkey: PublicKey,
    pub sig_len_bytes: u8,
    pub author_sig: Signature,
}

/**
 * TODO: During validity check, ensure that provided pubkey
 * hashes to the provided address.
 */
impl Transaction {

    pub fn new(txn_type: TransactionType,
               author_seckey: SecretKey,
               author_pubkey: PublicKey) -> Result<Transaction> {

        // Compute author's address from public key.
        let author_addr = address::from_pubkey(&author_pubkey).unwrap();

        // Compute and sign checksum.
        let checksum = Self::checksum(
                &txn_type, &author_addr, &author_pubkey);
        let checksum_msg = Message::from_slice(&checksum[..]).unwrap();
        let context = Secp256k1::new();
        let author_sig= context.sign(&checksum_msg, &author_seckey).unwrap();

        let txn = Transaction {
            txn_type: txn_type,
            author_addr: author_addr,
            author_pubkey: author_pubkey,
            sig_len_bytes: author_sig.len() as u8,
            author_sig: author_sig,
        };

        assert!(txn.has_valid_signature());
        Ok(txn)
    }

    pub fn deserialize<R: Read>(mut reader: R) -> Result<Transaction> {

        let txn_type = match reader.read_u8().unwrap() {
            TRUST_TXN_TYPE => {
                let addr = address::deserialize(&mut reader).unwrap();
                TransactionType::Trust(addr)
            },
            REVOKE_TRUST_TXN_TYPE => {
                let addr = address::deserialize(&mut reader).unwrap();
                TransactionType::RevokeTrust(addr)
            },
            CERTIFY_TXN_TYPE => {
                let mut doc_checksum_buf = [0u8; 32];
                reader.read(&mut doc_checksum_buf).unwrap();
                TransactionType::Certify(
                    DoubleSha256Hash::from_slice(&doc_checksum_buf[..]))
            },
            REVOKE_CERTIFICATION_TXN_TYPE => {
                let mut certify_txn_id_buf = [0u8; 32];
                reader.read(&mut certify_txn_id_buf).unwrap();
                TransactionType::RevokeCertification(
                    DoubleSha256Hash::from_slice(&certify_txn_id_buf[..]))
            },
            i => panic!("Attempted to deserialize unsupported txn_type\
                        magic: {}", i)
        };

        let author_addr = address::deserialize(&mut reader).unwrap();
        let author_pubkey = key::deserialize_pubkey(&mut reader).unwrap();
        let sig_len_bytes = reader.read_u8().unwrap();
        let txn = Transaction {
            txn_type: txn_type,
            author_addr: author_addr,
            author_pubkey: author_pubkey,
            sig_len_bytes: sig_len_bytes,
            author_sig: transaction::deserialize_signature(
                &mut reader, sig_len_bytes).unwrap(),
        };

        assert!(txn.has_valid_signature());
        Ok(txn)
    }

    pub fn serialize<W: Write>(&self, mut writer: W) -> Result<()> {
        Self::serialize_txn_type(&self.txn_type, &mut writer).unwrap();
        self.author_addr.serialize(&mut writer).unwrap();
        key::serialize_pubkey(&self.author_pubkey, &mut writer).unwrap();
        self.serialize_signature(&mut writer).unwrap();
        Ok(())
    }

    fn checksum(txn_type: &TransactionType,
                author_addr: &Address,
                author_pubkey: &PublicKey) -> DoubleSha256Hash {
        let mut buf = Vec::new();
        Self::serialize_txn_type(&txn_type, &mut buf).unwrap();
        author_addr.serialize(&mut buf).unwrap();
        key::serialize_pubkey(&author_pubkey, &mut buf).unwrap();
        DoubleSha256Hash::hash(&buf[..])
    }

    pub fn has_valid_signature(&self) -> bool {
        let checksum = Self::checksum(&self.txn_type, &self.author_addr, &self.author_pubkey);
        info!("[SigValidity] checksum: {:?}", &checksum);
        let checksum_msg = Message::from_slice(&checksum[..]).unwrap();
        info!("[SigValidity] msg: {:?}", &checksum_msg);
        let context = Secp256k1::new();
        info!("[SigValidity] pubkey: {:?}", &self.author_pubkey);
        match context.verify(&checksum_msg, &self.author_sig, &self.author_pubkey) {
            Ok(_) => {
                info!("Signature is valid: {:?}", &self.author_sig);
                true
            }
            Err(e) => {
                error!("Signature is invalid {:?}; reason: {:?}", &self.author_sig, e);
                false
            }
        }
    }
    pub fn serialize_signature<W: Write>(&self, mut writer: W) -> Result<()> {
        info!("Serializing signature of length: {}", &self.sig_len_bytes);
        info!("Serialized sig_buf: {:?}", &self.author_sig[..]);
        assert_eq!(self.author_sig[..].len(), self.sig_len_bytes as usize);
        assert!((self.sig_len_bytes as usize) <= MAX_SIGNATURE_LEN_BYTES);
        writer.write(&self.author_sig[..]).unwrap();
        Ok(())
    }

    pub fn serialize_txn_type<W: Write>(txn_type: &TransactionType, mut writer: W) -> Result<()> {
        match *txn_type {
            TransactionType::Trust(addr) => {
                writer.write_u8(TRUST_TXN_TYPE).unwrap();
                addr.serialize(&mut writer).unwrap();
            },
            TransactionType::RevokeTrust(addr) => {
                writer.write_u8(REVOKE_TRUST_TXN_TYPE).unwrap();
                addr.serialize(&mut writer).unwrap();
            },
            TransactionType::Certify(ref doc_checksum) => {
                writer.write_u8(CERTIFY_TXN_TYPE).unwrap();
                writer.write(&doc_checksum[..]).unwrap();
            },
            TransactionType::RevokeCertification(ref txn_id) => {
                writer.write_u8(REVOKE_CERTIFICATION_TXN_TYPE).unwrap();
                writer.write(&txn_id[..]).unwrap();
            }
        };
        Ok(())
    }
}

pub fn deserialize_signature<R: Read>(reader: R,
            sig_len_bytes: u8) -> Result<Signature> {
    let mut sig_buf = Vec::new();
    try!(reader.take(sig_len_bytes as u64).read_to_end(&mut sig_buf));
    info!("Deserialized sig_buf: {:?}", &sig_buf[..]);
    let sig = Signature::from_slice(&sig_buf[..]).unwrap();
    Ok(sig)
}


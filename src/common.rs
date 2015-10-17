#[derive(Debug)]
pub enum ValidityErr {
    InstAddressLength,
    InstAddressVersionPrefix,
    InstAddressChecksum,
    ToInstAddrInvalid,
    ToInstAddrDoesntMatchOurs,
    ToHostNameDoesntMatchOurs,
    ToPortDoesntMatchOurs,
    FromInstAddrInvalid,
    UnableToRecoverFromAddrPubkey,
    RecoveredFromAddrInvalid,
    RecoveredFromAddrDoesntMatch,
    Secp256k1MessageInvalidErr,
    Secp256k1PubkeyRecoveryErr,
    NonceDoesntMatch,
}

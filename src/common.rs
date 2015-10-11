#[derive(Debug)]
pub enum ValidityErr {
    InstAddressLength,
    InstAddressVersionPrefix,
    InstAddressChecksum,
}

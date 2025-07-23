use std::str::FromStr;

use error_stack::{ensure, report, Report, Result, ResultExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const ADDRESS_PREFIX: &str = "0x";
const SUI_ADDRESS_LENGTH: usize = 32;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid address length: {:?}", .0)]
    InvalidAddressLength(Vec<u8>),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SuiAddress([u8; SUI_ADDRESS_LENGTH]);

impl SuiAddress {
    pub fn as_bytes(&self) -> &[u8; SUI_ADDRESS_LENGTH] {
        &self.0
    }
}

impl TryFrom<&[u8]> for SuiAddress {
    type Error = Report<Error>;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .try_into()
            .map(Self)
            .change_context(Error::InvalidAddressLength(bytes.to_vec()))
    }
}

impl FromStr for SuiAddress {
    type Err = Report<Error>;

    fn from_str(s: &str) -> Result<Self, Error> {
        let hex = s
            .strip_prefix(ADDRESS_PREFIX)
            .ok_or(report!(Error::InvalidAddress(s.to_string())))?;
        // disallow uppercase characters for the sui addresses
        ensure!(
            hex.to_lowercase() == hex,
            Error::InvalidAddress(s.to_string())
        );

        hex::decode(hex)
            .change_context(Error::InvalidAddress(s.to_string()))?
            .as_slice()
            .try_into()
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;

    #[test]
    fn sui_address_try_from() {
        let mut bytes = [0u8; SUI_ADDRESS_LENGTH];
        rand::thread_rng().fill_bytes(&mut bytes);
        let address = SuiAddress::try_from(&bytes[..]).unwrap();
        assert_eq!(address.as_bytes(), &bytes);

        let mut bytes = [0u8; SUI_ADDRESS_LENGTH + 1];
        rand::thread_rng().fill_bytes(&mut bytes);
        assert!(SuiAddress::try_from(&bytes[..]).is_err());

        let mut bytes = [0u8; SUI_ADDRESS_LENGTH - 1];
        rand::thread_rng().fill_bytes(&mut bytes);
        assert!(SuiAddress::try_from(&bytes[..]).is_err());
    }

    #[test]
    fn sui_address_from_str() {
        let mut bytes = [0u8; SUI_ADDRESS_LENGTH];
        rand::thread_rng().fill_bytes(&mut bytes);
        let address = SuiAddress::from_str(format!("0x{}", hex::encode(bytes)).as_str()).unwrap();
        assert_eq!(address.as_bytes(), &bytes);

        let mut bytes = [0u8; SUI_ADDRESS_LENGTH + 1];
        rand::thread_rng().fill_bytes(&mut bytes);
        assert!(SuiAddress::from_str(format!("0x{}", hex::encode(bytes)).as_str()).is_err());

        let mut bytes = [0u8; SUI_ADDRESS_LENGTH - 1];
        rand::thread_rng().fill_bytes(&mut bytes);
        assert!(SuiAddress::from_str(format!("0x{}", hex::encode(bytes)).as_str()).is_err());

        let mut bytes = [0u8; SUI_ADDRESS_LENGTH];
        rand::thread_rng().fill_bytes(&mut bytes);
        assert!(SuiAddress::from_str(format!("0x0x{}", hex::encode(bytes)).as_str()).is_err());

        let mut bytes = [0u8; SUI_ADDRESS_LENGTH];
        rand::thread_rng().fill_bytes(&mut bytes);
        assert!(SuiAddress::from_str(format!("test{}", hex::encode(bytes)).as_str()).is_err());

        let mut bytes = [0u8; SUI_ADDRESS_LENGTH];
        rand::thread_rng().fill_bytes(&mut bytes);
        assert!(SuiAddress::from_str(hex::encode(bytes).as_str()).is_err());
    }
}

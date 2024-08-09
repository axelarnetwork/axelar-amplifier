use std::str::FromStr;

use error_stack::{report, Report, Result, ResultExt};
use serde::{Deserialize, Serialize};

use crate::error::Error;

const ADDRESS_PREFIX: &str = "0x";
const SUI_ADDRESS_LENGTH: usize = 32;

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
            .change_context(Error::InvalidAddressBytes(bytes.to_vec()))
    }
}

impl FromStr for SuiAddress {
    type Err = Report<Error>;

    fn from_str(s: &str) -> Result<Self, Error> {
        hex::decode(
            s.strip_prefix(ADDRESS_PREFIX)
                .ok_or(report!(Error::InvalidAddressHex(s.to_string())))?,
        )
        .change_context(Error::InvalidAddressHex(s.to_string()))?
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

use std::str::FromStr;

use error_stack::{Report, Result, ResultExt};
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
        hex::decode(s.trim_start_matches(ADDRESS_PREFIX))
            .change_context(Error::InvalidAddressHex(s.to_string()))?
            .as_slice()
            .try_into()
    }
}

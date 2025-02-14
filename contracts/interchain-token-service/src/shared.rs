use core::fmt;
use std::ops::Deref;

use axelar_wasm_std::IntoContractError;
use cosmwasm_schema::cw_serde;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, IntoContractError)]
pub enum Error {
    #[error("invalid number of bits {0}. Must be 32, 64, 128 or 256")]
    InvalidNumberOfBits(u32),
}

#[cw_serde]
#[serde(try_from = "u32")]
pub struct NumBits(u32);

impl TryFrom<u32> for NumBits {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            32 | 64 | 128 | 256 => Ok(Self(value)),
            _ => Err(Error::InvalidNumberOfBits(value)),
        }
    }
}

impl Deref for NumBits {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for NumBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::assert_err_contains;

    use crate::shared::{Error, NumBits};

    #[test]
    fn should_parse_valid_values() {
        let cases = [32, 64, 128, 256];
        for case in cases {
            assert!(NumBits::try_from(case).is_ok());
            assert_eq!(*NumBits::try_from(case).unwrap(), case)
        }
    }

    #[test]
    fn should_not_parse_invalid_values() {
        let cases = [0, 1, 16, 33, 255, 512];
        for case in cases {
            assert_err_contains!(
                NumBits::try_from(case),
                Error,
                Error::InvalidNumberOfBits(..)
            );
        }
    }
}

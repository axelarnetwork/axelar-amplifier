use core::fmt;

use axelar_wasm_std::IntoContractError;
use cosmwasm_schema::cw_serde;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, IntoContractError)]
pub enum Error {
    #[error("number of bits must be between 1 and 256 (given: {0})")]
    InvalidNumberOfBits(u32),
}

#[cw_serde]
#[derive(PartialOrd, Copy)]
#[serde(try_from = "u32", into = "u32")]
pub struct NumBits(u8);

impl TryFrom<u32> for NumBits {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        value
            .checked_sub(1)
            .and_then(|value| u8::try_from(value).ok())
            .ok_or(Error::InvalidNumberOfBits(value))
            .map(Self)
    }
}

impl From<NumBits> for u32 {
    fn from(value: NumBits) -> Self {
        (value.0 as u32)
            .checked_add(1)
            .expect("u8::MAX + 1 < u32::MAX")
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
        let cases = [1, 10, 32, 50, 64, 100, 127, 128, 255, 256];
        for case in cases {
            assert!(NumBits::try_from(case).is_ok());
            assert_eq!(u32::from(NumBits::try_from(case).unwrap()), case)
        }
    }

    #[test]
    fn should_not_parse_invalid_values() {
        let cases = [0, 257, 512, 10000];
        for case in cases {
            assert_err_contains!(
                NumBits::try_from(case),
                Error,
                Error::InvalidNumberOfBits(..)
            );
        }
    }
}

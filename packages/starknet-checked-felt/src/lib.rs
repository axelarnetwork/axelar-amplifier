use std::ops::Deref;
use std::str::FromStr;

use alloy_primitives::U256;
use hex::FromHexError;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use thiserror::Error;

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
/// A type that wraps the `starknet_types_core::felt::Felt` type
/// and makes sure that it doesn't overflow the
/// `starknet_types_core::felt::Felt::MAX` value
pub struct CheckedFelt(Felt);

#[derive(Error, Debug, PartialEq)]
pub enum CheckedFeltError {
    #[error("Felt value overflowing the Felt::MAX, value")]
    Overflowing,
    #[error("failed to decode hex string: {0}")]
    HexDecode(#[from] FromHexError),
}

// Decimal - 3618502788666131213697322783095070105623107215331596699973092056135872020480
// Hex - 800000000000011000000000000000000000000000000000000000000000000
const FELT_MAX_U256: U256 = U256::from_be_bytes::<32>([
    8, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

impl TryFrom<&[u8; 32]> for CheckedFelt {
    type Error = CheckedFeltError;

    fn try_from(value: &[u8; 32]) -> Result<Self, Self::Error> {
        if U256::from_be_bytes::<32>(*value) > FELT_MAX_U256 {
            return Err(CheckedFeltError::Overflowing);
        }

        Ok(CheckedFelt(Felt::from_bytes_be(value)))
    }
}

impl TryFrom<&[u8]> for CheckedFelt {
    type Error = CheckedFeltError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() > 32 {
            return Err(CheckedFeltError::Overflowing);
        }

        if U256::from_be_slice(value) > FELT_MAX_U256 {
            return Err(CheckedFeltError::Overflowing);
        }

        Ok(CheckedFelt(Felt::from_bytes_be_slice(value)))
    }
}

impl TryFrom<U256> for CheckedFelt {
    type Error = CheckedFeltError;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value > FELT_MAX_U256 {
            return Err(CheckedFeltError::Overflowing);
        }

        Ok(CheckedFelt(Felt::from_bytes_be(&value.to_be_bytes::<32>())))
    }
}

impl TryFrom<&str> for CheckedFelt {
    type Error = CheckedFeltError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        CheckedFelt::from_str(value)
    }
}

/// Creates a `CheckedFelt` from a hex string value
impl FromStr for CheckedFelt {
    type Err = CheckedFeltError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let felt_hex_str = s.trim_start_matches("0x");
        let felt_hex_bytes = hex::decode(felt_hex_str)?;

        if U256::from_be_slice(felt_hex_bytes.as_slice())
            > U256::from_be_bytes(Felt::MAX.to_bytes_be())
        {
            return Err(CheckedFeltError::Overflowing);
        }

        Ok(CheckedFelt(Felt::from_bytes_be_slice(
            felt_hex_bytes.as_slice(),
        )))
    }
}

impl From<CheckedFelt> for Felt {
    fn from(value: CheckedFelt) -> Self {
        value.0
    }
}

impl From<Felt> for CheckedFelt {
    fn from(value: Felt) -> Self {
        CheckedFelt(value)
    }
}

impl std::fmt::Display for CheckedFelt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for CheckedFelt {
    type Target = Felt;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::LowerHex for CheckedFelt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = self.0;

        std::fmt::LowerHex::fmt(&val, f)
    }
}

impl AsRef<Felt> for CheckedFelt {
    fn as_ref(&self) -> &Felt {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    // use core::slice::SlicePattern;
    use std::str::FromStr;

    use alloy_primitives::U256;
    use starknet_types_core::felt::Felt;

    use super::{CheckedFelt, CheckedFeltError};

    // same as valid, but with 9, instead 0 for first char
    const OVERFLOWING_FELT: &str =
        "949ec69cd2e0c987857fbda7966ff59077e2e92c18959bdb9b0012438c452047";
    const VALID_FELT: &str = "049ec69cd2e0c987857fbda7966ff59077e2e92c18959bdb9b0012438c452047";

    #[test]
    fn should_create_from_u256() {
        let felt = hex::decode(VALID_FELT).unwrap();
        let felt_u256: U256 = U256::from_be_slice(felt.as_slice());
        let actual = CheckedFelt::try_from(felt_u256).unwrap();
        let expected = Felt::from_hex(VALID_FELT).unwrap();

        assert_eq!(expected, actual.0);
    }

    #[test]
    fn should_create_from_str() {
        let actual = CheckedFelt::from_str(VALID_FELT).unwrap();
        let expected = Felt::from_hex(VALID_FELT).unwrap();
        assert_eq!(expected, actual.0);

        let actual = CheckedFelt::try_from(VALID_FELT).unwrap();
        let expected = Felt::from_hex(VALID_FELT).unwrap();
        assert_eq!(expected, actual.0);
    }

    #[test]
    fn should_create_from_bytes32() {
        let felt = hex::decode(VALID_FELT).unwrap();
        let actual = CheckedFelt::try_from(felt.as_slice()).unwrap();
        let expected = Felt::from_hex(VALID_FELT).unwrap();

        assert_eq!(expected, actual.0);
    }

    #[test]
    fn should_create_from_slice() {
        let felt = hex::decode(VALID_FELT).unwrap();
        let actual = CheckedFelt::try_from(felt.as_slice()).unwrap();
        let expected = Felt::from_hex(VALID_FELT).unwrap();

        assert_eq!(expected, actual.0);
    }

    #[test]
    fn should_not_create_from_overflowing_str() {
        let actual = CheckedFelt::from_str(OVERFLOWING_FELT);
        let expected = CheckedFeltError::Overflowing;
        assert_eq!(expected, actual.unwrap_err());

        let actual = CheckedFelt::try_from(OVERFLOWING_FELT);
        assert_eq!(expected, actual.unwrap_err());
    }

    #[test]
    fn should_not_create_from_overflowing_u256() {
        let felt = hex::decode(OVERFLOWING_FELT).unwrap();
        let overflowing_felt_u256: U256 = U256::from_be_slice(felt.as_slice());
        let actual = CheckedFelt::try_from(overflowing_felt_u256);
        let expected = CheckedFeltError::Overflowing;

        assert_eq!(expected, actual.unwrap_err());
    }

    #[test]
    fn should_not_create_from_more_than_32_bytes() {
        let mut felt = hex::decode(VALID_FELT).unwrap();
        felt.push(1); // add a 33rd byte
        let actual = CheckedFelt::try_from(felt.as_slice());
        let expected = CheckedFeltError::Overflowing;

        assert_eq!(expected, actual.unwrap_err());
    }
}

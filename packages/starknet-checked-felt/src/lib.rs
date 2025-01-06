use std::ops::Deref;
use std::str::FromStr;

use alloy_primitives::U256;
use error_stack::{ensure, Report};
use hex::FromHexError;
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use thiserror::Error;

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
/// A type that wraps the `starknet_types_core::felt::Felt` type
/// and makes sure that it doesn't overflow the
/// `starknet_types_core::felt::Felt::MAX` value
///
/// Contract addresses in Starknet are Felts, which are decimals in a
/// prime field, which fit in 252 bytes and can't exceed that prime field.
/// We'll only accept hex representation of the Felts, because they're the most
/// commonly used representation for addresses.
///
/// We'll only accept 64 char hex strings.
/// 62 and 63 hex string chars is also a valid address but we expect those to be padded
/// with zeroes.
pub struct CheckedFelt(Felt);

#[derive(Error, Debug, PartialEq)]
pub enum CheckedFeltError {
    #[error("0x prefix is missing")]
    AddressPrefix,
    #[error("hex string is not 64 chars")]
    AddressLength,
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

impl TryFrom<&[u8]> for CheckedFelt {
    type Error = Report<CheckedFeltError>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        ensure!(value.len() <= 32, CheckedFeltError::Overflowing);
        ensure!(
            U256::from_be_slice(value) <= FELT_MAX_U256,
            CheckedFeltError::Overflowing
        );

        Ok(CheckedFelt(Felt::from_bytes_be_slice(value)))
    }
}

impl TryFrom<&[u8; 32]> for CheckedFelt {
    type Error = Report<CheckedFeltError>;

    fn try_from(value: &[u8; 32]) -> Result<Self, Self::Error> {
        Self::try_from(&value[..])
    }
}

impl TryFrom<U256> for CheckedFelt {
    type Error = Report<CheckedFeltError>;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        ensure!(value <= FELT_MAX_U256, CheckedFeltError::Overflowing);

        Ok(CheckedFelt(Felt::from_bytes_be(&value.to_be_bytes::<32>())))
    }
}

impl TryFrom<&str> for CheckedFelt {
    type Error = Report<CheckedFeltError>;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        CheckedFelt::from_str(value)
    }
}

/// Creates a `CheckedFelt` from a hex string value
impl FromStr for CheckedFelt {
    type Err = Report<CheckedFeltError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ensure!(s.starts_with("0x"), CheckedFeltError::AddressPrefix);

        let trimmed_addr = s.trim_start_matches("0x");
        ensure!(trimmed_addr.len() == 64, CheckedFeltError::AddressLength);

        let felt_hex_bytes = hex::decode(trimmed_addr).map_err(CheckedFeltError::HexDecode)?;

        Self::try_from(U256::from_be_slice(felt_hex_bytes.as_slice()))
    }
}

impl From<CheckedFelt> for Felt {
    fn from(value: CheckedFelt) -> Self {
        value.0
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy_primitives::U256;
    use axelar_wasm_std::assert_err_contains;
    use hex::FromHexError;
    use starknet_types_core::felt::Felt;

    use super::{CheckedFelt, CheckedFeltError};

    // same as valid, but with 9, instead 0 for first char
    const INVALID_HEX: &str = "0xzz9ec69cd2e0c987857fbda7966ff59077e2e92c18959bdb9b0012438c452047";
    const NO_PREFIX_FELT: &str = "049ec69cd2e0c987857fbda7966ff59077e2e92c18959bdb9b0012438c452047";
    const WRONG_LENGTH_FELT: &str =
        "0x00049ec69cd2e0c987857fbda7966ff59077e2e92c18959bdb9b0012438c452047";
    const OVERFLOWING_FELT: &str =
        "0x949ec69cd2e0c987857fbda7966ff59077e2e92c18959bdb9b0012438c452047";
    const VALID_FELT: &str = "0x049ec69cd2e0c987857fbda7966ff59077e2e92c18959bdb9b0012438c452047";

    #[test]
    fn should_create_from_u256() {
        let trimmed_addr = VALID_FELT.trim_start_matches("0x");

        let felt = hex::decode(trimmed_addr).unwrap();
        let felt_u256: U256 = U256::from_be_slice(felt.as_slice());
        let actual = CheckedFelt::try_from(felt_u256).unwrap();
        let expected = Felt::from_hex(trimmed_addr).unwrap();

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
        let trimmed_addr = VALID_FELT.trim_start_matches("0x");

        let felt = hex::decode(trimmed_addr).unwrap();
        let actual = CheckedFelt::try_from(felt.as_slice()).unwrap();
        let expected = Felt::from_hex(trimmed_addr).unwrap();

        assert_eq!(expected, actual.0);
    }

    #[test]
    fn should_create_from_slice() {
        let trimmed_addr = VALID_FELT.trim_start_matches("0x");

        let felt = hex::decode(trimmed_addr).unwrap();
        let actual = CheckedFelt::try_from(felt.as_slice()).unwrap();
        let expected = Felt::from_hex(trimmed_addr).unwrap();

        assert_eq!(expected, actual.0);
    }

    #[test]
    fn should_not_create_from_invalid_hex() {
        assert_err_contains!(
            CheckedFelt::from_str(INVALID_HEX),
            CheckedFeltError,
            CheckedFeltError::HexDecode(FromHexError::InvalidHexCharacter { c: 'z', index: 0 })
        );
    }

    #[test]
    fn should_not_create_from_felt_with_no_prefix() {
        assert_err_contains!(
            CheckedFelt::from_str(NO_PREFIX_FELT),
            CheckedFeltError,
            CheckedFeltError::AddressPrefix
        );
    }

    #[test]
    fn should_not_create_from_felt_with_wrong_hex_string_length() {
        assert_err_contains!(
            CheckedFelt::from_str(WRONG_LENGTH_FELT),
            CheckedFeltError,
            CheckedFeltError::AddressLength
        );
    }

    #[test]
    fn should_not_create_from_overflowing_str() {
        assert_err_contains!(
            CheckedFelt::from_str(OVERFLOWING_FELT),
            CheckedFeltError,
            CheckedFeltError::Overflowing
        );

        assert_err_contains!(
            CheckedFelt::try_from(OVERFLOWING_FELT),
            CheckedFeltError,
            CheckedFeltError::Overflowing
        );
    }

    #[test]
    fn should_not_create_from_overflowing_u256() {
        let trimmed_addr = OVERFLOWING_FELT.trim_start_matches("0x");
        let felt = hex::decode(trimmed_addr).unwrap();
        let overflowing_felt_u256: U256 = U256::from_be_slice(felt.as_slice());

        assert_err_contains!(
            CheckedFelt::try_from(overflowing_felt_u256),
            CheckedFeltError,
            CheckedFeltError::Overflowing
        );
    }

    #[test]
    fn should_not_create_from_more_than_32_bytes() {
        let trimmed_addr = VALID_FELT.trim_start_matches("0x");
        let mut felt = hex::decode(trimmed_addr).unwrap();
        felt.push(1); // add a 33rd byte

        assert_err_contains!(
            CheckedFelt::try_from(felt.as_slice()),
            CheckedFeltError,
            CheckedFeltError::Overflowing
        );
    }
}

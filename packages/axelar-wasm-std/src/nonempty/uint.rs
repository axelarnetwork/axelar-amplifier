use std::fmt;

use crate::nonempty::Error;
use cosmwasm_schema::cw_serde;

#[cw_serde]
#[derive(Copy, PartialOrd)]
pub struct Uint64(cosmwasm_std::Uint64);

impl TryFrom<cosmwasm_std::Uint64> for Uint64 {
    type Error = Error;

    fn try_from(value: cosmwasm_std::Uint64) -> Result<Self, Self::Error> {
        if value.is_zero() {
            Err(Error::InvalidValue(value.into()))
        } else {
            Ok(Uint64(value))
        }
    }
}

impl TryFrom<u64> for Uint64 {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        cosmwasm_std::Uint64::from(value).try_into()
    }
}

impl<'a> From<&'a Uint64> for &'a cosmwasm_std::Uint64 {
    fn from(value: &'a Uint64) -> Self {
        &value.0
    }
}

impl From<Uint64> for cosmwasm_std::Uint64 {
    fn from(value: Uint64) -> Self {
        value.0
    }
}

impl fmt::Display for Uint64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// TODO: consider using macro for these types
#[cw_serde]
#[derive(Copy, PartialOrd, Eq)]
pub struct Uint256(cosmwasm_std::Uint256);

impl TryFrom<cosmwasm_std::Uint256> for Uint256 {
    type Error = Error;

    fn try_from(value: cosmwasm_std::Uint256) -> Result<Self, Self::Error> {
        if value == cosmwasm_std::Uint256::zero() {
            Err(Error::InvalidValue(value.into()))
        } else {
            Ok(Uint256(value))
        }
    }
}

impl From<Uint256> for cosmwasm_std::Uint256 {
    fn from(value: Uint256) -> Self {
        value.0
    }
}

impl<'a> From<&'a Uint256> for &'a cosmwasm_std::Uint256 {
    fn from(value: &'a Uint256) -> Self {
        &value.0
    }
}

impl TryFrom<cosmwasm_std::Uint128> for Uint256 {
    type Error = Error;

    fn try_from(value: cosmwasm_std::Uint128) -> Result<Self, Self::Error> {
        if value == cosmwasm_std::Uint128::zero() {
            Err(Error::InvalidValue(value.into()))
        } else {
            Ok(Uint256(value.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_zero_uint64() {
        assert!(Uint64::try_from(cosmwasm_std::Uint64::one()).is_ok());
        assert!(Uint64::try_from(1u64).is_ok());
    }

    #[test]
    fn test_zero_non_zero_uint64() {
        assert_eq!(
            Uint64::try_from(cosmwasm_std::Uint64::zero()).unwrap_err(),
            Error::InvalidValue("0".into())
        );
        assert_eq!(
            Uint64::try_from(0u64).unwrap_err(),
            Error::InvalidValue("0".into())
        );
    }

    #[test]
    fn test_non_zero_uint256() {
        assert!(Uint256::try_from(cosmwasm_std::Uint256::one()).is_ok());
    }

    #[test]
    fn test_zero_non_zero_uint256() {
        assert_eq!(
            Uint256::try_from(cosmwasm_std::Uint256::zero()).unwrap_err(),
            Error::InvalidValue("0".into())
        );
    }
}

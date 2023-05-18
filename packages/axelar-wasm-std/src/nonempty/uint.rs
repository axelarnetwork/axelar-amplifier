use std::cmp::Ordering;

use crate::nonempty::Error;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Uint256, Uint64};

#[cw_serde]
#[derive(Copy)]
pub struct NonZeroUint64(Uint64);

impl TryFrom<Uint64> for NonZeroUint64 {
    type Error = Error;

    fn try_from(value: Uint64) -> Result<Self, Self::Error> {
        if value.is_zero() {
            Err(Error::InvalidValue(value.into()))
        } else {
            Ok(NonZeroUint64(value))
        }
    }
}

impl TryFrom<u64> for NonZeroUint64 {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Uint64::from(value).try_into()
    }
}

impl<'a> From<&'a NonZeroUint64> for &'a Uint64 {
    fn from(value: &'a NonZeroUint64) -> Self {
        &value.0
    }
}

impl From<NonZeroUint64> for Uint64 {
    fn from(value: NonZeroUint64) -> Self {
        value.0
    }
}

impl PartialOrd for NonZeroUint64 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

// TODO: consider using macro for these types
#[cw_serde]
#[derive(Copy)]
pub struct NonZeroUint256(Uint256);

impl TryFrom<Uint256> for NonZeroUint256 {
    type Error = Error;

    fn try_from(value: Uint256) -> Result<Self, Self::Error> {
        if value == Uint256::zero() {
            Err(Error::InvalidValue(value.into()))
        } else {
            Ok(NonZeroUint256(value))
        }
    }
}

impl<'a> From<&'a NonZeroUint256> for &'a Uint256 {
    fn from(value: &'a NonZeroUint256) -> Self {
        &value.0
    }
}

impl PartialOrd for NonZeroUint256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_zero_uint64() {
        assert!(NonZeroUint64::try_from(Uint64::one()).is_ok());
        assert!(NonZeroUint64::try_from(1u64).is_ok());
    }

    #[test]
    fn test_zero_non_zero_uint64() {
        assert_eq!(
            NonZeroUint64::try_from(Uint64::zero()).unwrap_err(),
            Error::InvalidValue("0".into())
        );
        assert_eq!(
            NonZeroUint64::try_from(0u64).unwrap_err(),
            Error::InvalidValue("0".into())
        );
    }

    #[test]
    fn test_non_zero_uint256() {
        assert!(NonZeroUint256::try_from(Uint256::one()).is_ok());
    }

    #[test]
    fn test_zero_non_zero_uint256() {
        assert_eq!(
            NonZeroUint256::try_from(Uint256::zero()).unwrap_err(),
            Error::InvalidValue("0".into())
        );
    }
}

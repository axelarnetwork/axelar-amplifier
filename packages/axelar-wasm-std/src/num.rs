use std::cmp::Ordering;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Timestamp, Uint256, Uint64};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum NumError {
    #[error("type cannot be zero")]
    Zero,
}

#[cw_serde]
#[derive(Copy)]
pub struct NonZeroUint64(Uint64);

impl TryFrom<Uint64> for NonZeroUint64 {
    type Error = NumError;

    fn try_from(value: Uint64) -> Result<Self, Self::Error> {
        if value.is_zero() {
            Err(NumError::Zero)
        } else {
            Ok(NonZeroUint64(value))
        }
    }
}

impl TryFrom<u64> for NonZeroUint64 {
    type Error = NumError;

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
    type Error = NumError;

    fn try_from(value: Uint256) -> Result<Self, Self::Error> {
        if value == Uint256::zero() {
            Err(NumError::Zero)
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

#[cw_serde]
pub struct NonZeroTimestamp(Timestamp);

impl TryFrom<Timestamp> for NonZeroTimestamp {
    type Error = NumError;

    fn try_from(value: Timestamp) -> Result<Self, Self::Error> {
        if value.nanos() == 0u64 {
            Err(NumError::Zero)
        } else {
            Ok(NonZeroTimestamp(value))
        }
    }
}

impl NonZeroTimestamp {
    pub fn try_from_nanos(value: u64) -> Result<Self, NumError> {
        if value == 0u64 {
            Err(NumError::Zero)
        } else {
            Ok(NonZeroTimestamp(Timestamp::from_nanos(value)))
        }
    }
}

impl<'a> From<&'a NonZeroTimestamp> for &'a Timestamp {
    fn from(value: &'a NonZeroTimestamp) -> Self {
        &value.0
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
            NumError::Zero
        );
        assert_eq!(NonZeroUint64::try_from(0u64).unwrap_err(), NumError::Zero);
    }

    #[test]
    fn test_non_zero_timestamp() {
        assert!(NonZeroTimestamp::try_from(Timestamp::from_nanos(1u64)).is_ok());
        assert!(NonZeroTimestamp::try_from_nanos(1u64).is_ok());
    }

    #[test]
    fn test_zero_non_zero_timestamp() {
        assert_eq!(
            NonZeroTimestamp::try_from(Timestamp::from_nanos(0u64)).unwrap_err(),
            NumError::Zero
        );
        assert_eq!(
            NonZeroTimestamp::try_from_nanos(0u64).unwrap_err(),
            NumError::Zero
        );
    }
}

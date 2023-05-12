use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Timestamp, Uint256, Uint64};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum NumError {
    #[error("cannot set zero to non-zero type")]
    Zero,
}

#[cw_serde]
pub struct NonZeroUint64(Uint64);

impl TryFrom<Uint64> for NonZeroUint64 {
    type Error = NumError;

    fn try_from(value: Uint64) -> Result<Self, Self::Error> {
        value.u64().try_into()
    }
}

impl TryFrom<u64> for NonZeroUint64 {
    type Error = NumError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == 0 {
            Err(NumError::Zero)
        } else {
            Ok(NonZeroUint64(Uint64::from(value)))
        }
    }
}

impl NonZeroUint64 {
    pub fn as_uint64(&self) -> &Uint64 {
        &self.0
    }
}

// TODO: consider using macro for these types
#[cw_serde]
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

impl NonZeroUint256 {
    pub fn as_uint256(&self) -> &Uint256 {
        &self.0
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

    pub fn as_timestamp(&self) -> &Timestamp {
        &self.0
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

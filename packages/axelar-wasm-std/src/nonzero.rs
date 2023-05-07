use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdError, Timestamp, Uint256, Uint64};

#[cw_serde]
pub struct NonZeroUint64(Uint64);

impl TryFrom<Uint64> for NonZeroUint64 {
    type Error = StdError;

    fn try_from(value: Uint64) -> Result<Self, Self::Error> {
        if value == Uint64::zero() {
            Err(zero_error())
        } else {
            Ok(NonZeroUint64(value))
        }
    }
}

impl TryFrom<u64> for NonZeroUint64 {
    type Error = StdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == 0u64 {
            Err(zero_error())
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
    type Error = StdError;

    fn try_from(value: Uint256) -> Result<Self, Self::Error> {
        if value == Uint256::zero() {
            Err(zero_error())
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
    type Error = StdError;

    fn try_from(value: Timestamp) -> Result<Self, Self::Error> {
        if value.nanos() == 0u64 {
            Err(zero_error())
        } else {
            Ok(NonZeroTimestamp(value))
        }
    }
}

impl NonZeroTimestamp {
    pub fn try_from_nanos(value: u64) -> Result<Self, StdError> {
        if value == 0u64 {
            Err(zero_error())
        } else {
            Ok(NonZeroTimestamp(Timestamp::from_nanos(value)))
        }
    }

    pub fn as_timestamp(&self) -> &Timestamp {
        &self.0
    }
}

fn zero_error() -> StdError {
    StdError::generic_err("Cannot set zero to non-zero type")
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
        let expected_error = zero_error().to_string();

        assert_eq!(
            NonZeroUint64::try_from(Uint64::zero())
                .unwrap_err()
                .to_string(),
            expected_error
        );
        assert_eq!(
            NonZeroUint64::try_from(0u64).unwrap_err().to_string(),
            expected_error
        );
    }

    #[test]
    fn test_non_zero_timestamp() {
        assert!(NonZeroTimestamp::try_from(Timestamp::from_nanos(1u64)).is_ok());
        assert!(NonZeroTimestamp::try_from_nanos(1u64).is_ok());
    }

    #[test]
    fn test_zero_non_zero_timestamp() {
        let expected_error = zero_error().to_string();

        assert_eq!(
            NonZeroTimestamp::try_from(Timestamp::from_nanos(0u64))
                .unwrap_err()
                .to_string(),
            expected_error
        );
        assert_eq!(
            NonZeroTimestamp::try_from_nanos(0u64)
                .unwrap_err()
                .to_string(),
            expected_error
        );
    }
}

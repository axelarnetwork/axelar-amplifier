use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Decimal256, StdError};

#[cw_serde]
pub struct Threshold(Decimal256);

impl TryFrom<Decimal256> for Threshold {
    type Error = StdError;

    fn try_from(value: Decimal256) -> Result<Self, Self::Error> {
        if value > Decimal256::one() || value.atomics().is_zero() {
            Err(out_of_bounds_error())
        } else {
            Ok(Threshold(value))
        }
    }
}

impl Threshold {
    pub fn as_decimal(&self) -> &Decimal256 {
        &self.0
    }
}

fn out_of_bounds_error() -> StdError {
    StdError::generic_err("Cannot set value out of (0, 1] bounds to threshold type")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_threshold() {
        assert!(Threshold::try_from(Decimal256::from_ratio(2u8, 3u8)).is_ok());
    }

    #[test]
    fn test_threshold_zero() {
        assert_eq!(
            Threshold::try_from(Decimal256::from_ratio(0u8, 3u8)).unwrap_err(),
            out_of_bounds_error()
        );
    }

    #[test]
    fn test_threshold_greater_than_one() {
        assert_eq!(
            Threshold::try_from(Decimal256::from_str("1.000000000000000001").unwrap()).unwrap_err(),
            out_of_bounds_error()
        );
    }
}

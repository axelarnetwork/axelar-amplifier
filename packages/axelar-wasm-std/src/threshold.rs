use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Fraction, StdError, Uint64};

#[cw_serde]
#[derive(Copy)]
pub struct Threshold(Uint64, Uint64);

impl Fraction<Uint64> for Threshold {
    fn numerator(&self) -> Uint64 {
        self.0
    }

    fn denominator(&self) -> Uint64 {
        self.1
    }

    fn inv(&self) -> Option<Self> {
        Some(Self(self.1, self.0))
    }
}

impl<T: Into<Uint64>> TryFrom<(T, T)> for Threshold {
    type Error = StdError;

    fn try_from(value: (T, T)) -> Result<Self, Self::Error> {
        Threshold::try_from_ratio(value.0, value.1)
    }
}

impl Threshold {
    pub fn try_from_ratio(
        numerator: impl Into<Uint64>,
        denominator: impl Into<Uint64>,
    ) -> Result<Self, StdError> {
        let numerator: Uint64 = numerator.into();
        let denominator: Uint64 = denominator.into();

        if numerator > denominator || numerator.is_zero() {
            Err(out_of_bounds_error())
        } else {
            Ok(Threshold(numerator, denominator))
        }
    }
}

fn out_of_bounds_error() -> StdError {
    StdError::generic_err("Cannot set value out of (0, 1] bounds to threshold type")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold() {
        assert!(Threshold::try_from((2u8, 3u8)).is_ok());
    }

    #[test]
    fn test_threshold_zero() {
        assert_eq!(
            Threshold::try_from((0u8, 3u8)).unwrap_err(),
            out_of_bounds_error()
        );
    }

    #[test]
    fn test_threshold_greater_than_one() {
        assert_eq!(
            Threshold::try_from((Uint64::MAX, Uint64::MAX - Uint64::one())).unwrap_err(),
            out_of_bounds_error()
        );
    }
}

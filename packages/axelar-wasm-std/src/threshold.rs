use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Fraction, Uint64};
use std::fmt::Debug;
use thiserror::Error;

use crate::{NonZeroUint64, NumError};

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("threshold must fall into the interval (0, 1]")]
    OutOfInterval,
    #[error("denominator cannot be zero")]
    ZeroDenominator,
}

#[cw_serde]
#[derive(Copy)]
pub struct Threshold(NonZeroUint64, NonZeroUint64);

impl Fraction<Uint64> for Threshold {
    fn numerator(&self) -> Uint64 {
        self.0.into()
    }

    fn denominator(&self) -> Uint64 {
        self.1.into()
    }

    fn inv(&self) -> Option<Self> {
        Some(Self(self.1, self.0))
    }
}

impl TryFrom<(NonZeroUint64, NonZeroUint64)> for Threshold {
    type Error = Error;

    fn try_from((numerator, denominator): (NonZeroUint64, NonZeroUint64)) -> Result<Self, Error> {
        if numerator > denominator {
            Err(Error::OutOfInterval)
        } else {
            Ok(Threshold(numerator, denominator))
        }
    }
}

impl TryFrom<(Uint64, Uint64)> for Threshold {
    type Error = Error;

    fn try_from(value: (Uint64, Uint64)) -> Result<Self, Error> {
        try_from(value)
    }
}

impl TryFrom<(u64, u64)> for Threshold {
    type Error = Error;

    fn try_from(value: (u64, u64)) -> Result<Self, Error> {
        try_from(value)
    }
}

fn try_from<T: TryInto<NonZeroUint64, Error = NumError>>(
    value: (T, T),
) -> Result<Threshold, Error> {
    let numerator: NonZeroUint64 = value.0.try_into().map_err(|_| Error::OutOfInterval)?;
    let denominator: NonZeroUint64 = value.1.try_into().map_err(|_| Error::ZeroDenominator)?;

    (numerator, denominator).try_into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold() {
        assert!(Threshold::try_from((2u64, 3u64)).is_ok());
    }

    #[test]
    fn test_threshold_zero_numerator() {
        assert_eq!(
            Threshold::try_from((0u64, 3u64)).unwrap_err(),
            Error::OutOfInterval
        );
    }

    #[test]
    fn test_threshold_zero_denominator() {
        assert_eq!(
            Threshold::try_from((2u64, 0u64)).unwrap_err(),
            Error::ZeroDenominator
        );
    }

    #[test]
    fn test_threshold_greater_than_one() {
        assert_eq!(
            Threshold::try_from((Uint64::MAX, Uint64::MAX - Uint64::one())).unwrap_err(),
            Error::OutOfInterval
        );
    }
}

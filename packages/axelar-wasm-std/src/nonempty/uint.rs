use std::fmt;
use std::ops::Deref;

use cosmwasm_schema::cw_serde;
use into_inner_derive::IntoInner;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::nonempty::Error;

#[derive(
    Debug, Copy, Clone, IntoInner, Serialize, Deserialize, PartialEq, PartialOrd, JsonSchema,
)]
#[serde(try_from = "usize")]
#[serde(into = "usize")]
pub struct Usize(usize);

impl TryFrom<usize> for Usize {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value == 0 {
            Err(Error::InvalidValue(value.to_string()))
        } else {
            Ok(Usize(value))
        }
    }
}

impl TryFrom<u32> for Usize {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            Err(Error::InvalidValue(value.to_string()))
        } else {
            Ok(Usize(value as usize))
        }
    }
}

impl TryFrom<i32> for Usize {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        if value <= 0 {
            Err(Error::InvalidValue(value.to_string()))
        } else {
            Ok(Usize(value as usize))
        }
    }
}

impl From<Usize> for usize {
    fn from(value: Usize) -> Self {
        value.into_inner()
    }
}

impl fmt::Display for Usize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cw_serde]
#[serde(try_from = "cosmwasm_std::Uint64")]
#[serde(into = "cosmwasm_std::Uint64")]
#[derive(Copy, PartialOrd, IntoInner)]
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

impl From<Uint64> for cosmwasm_std::Uint64 {
    fn from(value: Uint64) -> Self {
        value.0
    }
}

impl From<Uint64> for u64 {
    fn from(value: Uint64) -> Self {
        value.0.into()
    }
}

impl fmt::Display for Uint64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// TODO: consider using macro for these types
#[cw_serde]
#[derive(Copy, PartialOrd, Eq, IntoInner)]
#[serde(try_from = "cosmwasm_std::Uint256")]
pub struct Uint256(cosmwasm_std::Uint256);

impl fmt::Display for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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

impl TryFrom<u64> for Uint256 {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        cosmwasm_std::Uint256::from(value).try_into()
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

impl Deref for Uint256 {
    type Target = cosmwasm_std::Uint256;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cw_serde]
#[derive(Copy, PartialOrd, Ord, Eq, IntoInner)]
pub struct Uint128(cosmwasm_std::Uint128);

impl TryFrom<cosmwasm_std::Uint128> for Uint128 {
    type Error = Error;

    fn try_from(value: cosmwasm_std::Uint128) -> Result<Self, Self::Error> {
        if value == cosmwasm_std::Uint128::zero() {
            Err(Error::InvalidValue(value.into()))
        } else {
            Ok(Uint128(value))
        }
    }
}

impl From<Uint128> for cosmwasm_std::Uint128 {
    fn from(value: Uint128) -> Self {
        value.0
    }
}

impl TryFrom<u128> for Uint128 {
    type Error = Error;
    fn try_from(value: u128) -> Result<Self, Self::Error> {
        cosmwasm_std::Uint128::from(value).try_into()
    }
}

impl Uint128 {
    pub const fn one() -> Self {
        Self(cosmwasm_std::Uint128::one())
    }
}

#[cw_serde]
#[derive(Copy, PartialOrd, Ord, Eq, IntoInner)]
pub struct Uint32(u32);

impl TryFrom<u32> for Uint32 {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            Err(Error::InvalidValue(value.to_string()))
        } else {
            Ok(Uint32(value))
        }
    }
}

impl TryFrom<i32> for Uint32 {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        if value <= 0 {
            Err(Error::InvalidValue(value.to_string()))
        } else {
            Ok(Uint32(value as u32))
        }
    }
}

impl From<Uint32> for u32 {
    fn from(value: Uint32) -> Self {
        value.0
    }
}

impl From<Uint32> for usize {
    fn from(value: Uint32) -> Self {
        value.0 as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_between_usize_and_nonempty_usize() {
        assert_eq!(
            Usize::try_from(0_usize).unwrap_err(),
            Error::InvalidValue("0".to_string())
        );
        assert_eq!(usize::from(Usize::try_from(100_usize).unwrap()), 100);
    }

    #[test]
    fn convert_from_u32_to_usize() {
        // zero
        assert_eq!(
            Usize::try_from(0u32).unwrap_err(),
            Error::InvalidValue("0".into())
        );

        // non-zero
        assert_eq!(usize::from(Usize::try_from(100u32).unwrap()), 100_usize);
    }

    #[test]
    fn convert_from_i32_to_usize() {
        // zero
        assert_eq!(
            Usize::try_from(0i32).unwrap_err(),
            Error::InvalidValue("0".into())
        );

        // non-zero
        assert_eq!(usize::from(Usize::try_from(100i32).unwrap()), 100_usize);
    }

    #[test]
    fn convert_from_u64_to_uint64() {
        // zero
        assert_eq!(
            Uint64::try_from(0u64).unwrap_err(),
            Error::InvalidValue("0".into())
        );

        // non-zero
        let val = 100u64;
        assert!(Uint64::try_from(val).is_ok());
        assert_eq!(val, u64::from(Uint64::try_from(val).unwrap()));
    }

    #[test]
    fn convert_from_cosmwasm_uint64_to_uint64() {
        // zero
        assert_eq!(
            Uint64::try_from(cosmwasm_std::Uint64::zero()).unwrap_err(),
            Error::InvalidValue("0".into())
        );

        // non-zero
        assert!(Uint64::try_from(cosmwasm_std::Uint64::one()).is_ok());
    }

    #[test]
    fn convert_from_cosmwasm_uint128_to_uint128() {
        // zero
        let val = cosmwasm_std::Uint128::zero();
        assert_eq!(
            Uint128::try_from(val).unwrap_err(),
            Error::InvalidValue(val.into())
        );

        // non-zero
        assert!(Uint128::try_from(cosmwasm_std::Uint128::one()).is_ok());
    }

    #[test]
    fn convert_from_cosmwasm_uint256_to_uint256() {
        // zero
        assert_eq!(
            Uint256::try_from(cosmwasm_std::Uint256::zero()).unwrap_err(),
            Error::InvalidValue("0".into())
        );

        // non-zero
        assert!(Uint256::try_from(cosmwasm_std::Uint256::one()).is_ok());
    }

    #[test]
    fn convert_from_cosmwasm_uint128_to_uint256() {
        // zero
        let val = cosmwasm_std::Uint128::zero();
        assert_eq!(
            Uint256::try_from(val).unwrap_err(),
            Error::InvalidValue(val.into())
        );

        // non-zero
        assert!(Uint256::try_from(cosmwasm_std::Uint128::one()).is_ok());
    }

    #[test]
    fn convert_from_uint128_to_non_empty_uint128() {
        assert!(Uint128::try_from(0u128).is_err());
        assert!(Uint128::try_from(1u128).is_ok());
    }

    #[test]
    fn convert_from_u32_to_uint32() {
        // zero
        assert_eq!(
            Uint32::try_from(0u32).unwrap_err(),
            Error::InvalidValue("0".into())
        );

        // non-zero
        assert_eq!(u32::from(Uint32::try_from(100u32).unwrap()), 100u32);
    }

    #[test]
    fn convert_from_i32_to_uint32() {
        // zero
        assert_eq!(
            Uint32::try_from(0i32).unwrap_err(),
            Error::InvalidValue("0".into())
        );

        // non-zero
        assert_eq!(u32::from(Uint32::try_from(100i32).unwrap()), 100u32);
    }
}

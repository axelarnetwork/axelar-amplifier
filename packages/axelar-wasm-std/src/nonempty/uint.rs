use std::fmt;

use crate::nonempty::Error;
use cosmwasm_schema::cw_serde;

#[cw_serde]
#[serde(try_from = "cosmwasm_std::Uint64")]
#[serde(into = "cosmwasm_std::Uint64")]
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

impl AsRef<cosmwasm_std::Uint256> for Uint256 {
    fn as_ref(&self) -> &cosmwasm_std::Uint256 {
        &self.0
    }
}

#[cw_serde]
#[derive(Copy, PartialOrd, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn convert_from_uint256_to_reference_cosmwasm_uint256() {
        let val = Uint256(cosmwasm_std::Uint256::one());
        let converted: &cosmwasm_std::Uint256 = val.as_ref();
        assert_eq!(&val.0, converted);
    }
}

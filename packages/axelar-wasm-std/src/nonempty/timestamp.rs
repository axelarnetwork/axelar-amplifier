use crate::nonempty::Error;
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct Timestamp(cosmwasm_std::Timestamp);

impl TryFrom<cosmwasm_std::Timestamp> for Timestamp {
    type Error = Error;

    fn try_from(value: cosmwasm_std::Timestamp) -> Result<Self, Self::Error> {
        if value.nanos() == 0u64 {
            Err(Error::InvalidValue("0".into()))
        } else {
            Ok(Timestamp(value))
        }
    }
}

impl<'a> From<&'a Timestamp> for &'a cosmwasm_std::Timestamp {
    fn from(value: &'a Timestamp) -> Self {
        &value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_zero_timestamp() {
        assert!(Timestamp::try_from(cosmwasm_std::Timestamp::from_nanos(1u64)).is_ok());
    }

    #[test]
    fn test_zero_non_zero_timestamp() {
        assert_eq!(
            Timestamp::try_from(cosmwasm_std::Timestamp::from_nanos(0u64)).unwrap_err(),
            Error::InvalidValue("0".into())
        );
    }
}

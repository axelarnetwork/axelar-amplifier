use crate::nonempty::Error;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Timestamp;

#[cw_serde]
pub struct NonZeroTimestamp(Timestamp);

impl TryFrom<Timestamp> for NonZeroTimestamp {
    type Error = Error;

    fn try_from(value: Timestamp) -> Result<Self, Self::Error> {
        if value.nanos() == 0u64 {
            Err(Error::InvalidValue("0".into()))
        } else {
            Ok(NonZeroTimestamp(value))
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
    fn test_non_zero_timestamp() {
        assert!(NonZeroTimestamp::try_from(Timestamp::from_nanos(1u64)).is_ok());
    }

    #[test]
    fn test_zero_non_zero_timestamp() {
        assert_eq!(
            NonZeroTimestamp::try_from(Timestamp::from_nanos(0u64)).unwrap_err(),
            Error::InvalidValue("0".into())
        );
    }
}

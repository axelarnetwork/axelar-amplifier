use crate::nonempty::Error;
use cosmwasm_schema::cw_serde;

#[cw_serde]
#[serde(try_from = "std::vec::Vec<T>")]
pub struct Vec<T>(std::vec::Vec<T>);

impl<T> TryFrom<std::vec::Vec<T>> for Vec<T> {
    type Error = Error;

    fn try_from(value: std::vec::Vec<T>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Error::InvalidValue("empty".to_string()))
        } else {
            Ok(Vec(value))
        }
    }
}

impl<T> From<Vec<T>> for std::vec::Vec<T> {
    fn from(value: Vec<T>) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_empty_vec() {
        assert!(Vec::try_from(vec![1, 2, 3]).is_ok())
    }

    #[test]
    fn test_empty_non_empty_vec() {
        assert_eq!(
            Vec::<u8>::try_from(vec![]).unwrap_err(),
            Error::InvalidValue("empty".to_string())
        )
    }
}

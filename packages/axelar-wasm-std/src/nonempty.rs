use cosmwasm_schema::cw_serde;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("type cannot be empty")]
    Empty,
}

#[cw_serde]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = Error;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Error::Empty)
        } else {
            Ok(NonEmptyVec(value))
        }
    }
}

impl<T> From<NonEmptyVec<T>> for Vec<T> {
    fn from(value: NonEmptyVec<T>) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_empty_vec() {
        assert!(NonEmptyVec::try_from(vec![1, 2, 3]).is_ok())
    }

    #[test]
    fn test_empty_non_empty_vec() {
        assert_eq!(
            NonEmptyVec::<u8>::try_from(vec![]).unwrap_err(),
            Error::Empty
        )
    }
}

use cosmwasm_schema::cw_serde;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum NonEmptyError {
    #[error("cannot set empty value to non-empty type")]
    Empty,
}

#[cw_serde]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = NonEmptyError;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(NonEmptyError::Empty)
        } else {
            Ok(NonEmptyVec(value))
        }
    }
}

impl<T> NonEmptyVec<T> {
    pub fn as_vec(&self) -> &Vec<T> {
        &self.0
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
            NonEmptyError::Empty
        )
    }
}

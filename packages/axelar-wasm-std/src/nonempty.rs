use cosmwasm_schema::cw_serde;
use cosmwasm_std::StdError;

#[cw_serde]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = StdError;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(empty_error())
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

fn empty_error() -> StdError {
    StdError::generic_err("cannot set empty vector to non-empty type")
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
            empty_error()
        )
    }
}

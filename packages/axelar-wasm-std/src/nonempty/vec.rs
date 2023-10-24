use crate::nonempty::Error;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;

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

impl TryFrom<&HexBinary> for Vec<u8> {
    type Error = Error;

    fn try_from(value: &HexBinary) -> Result<Self, Self::Error> {
        Vec::try_from(value.to_vec())
    }
}

impl<T> From<Vec<T>> for std::vec::Vec<T> {
    fn from(value: Vec<T>) -> Self {
        value.0
    }
}

impl<T> Vec<T> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        false
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

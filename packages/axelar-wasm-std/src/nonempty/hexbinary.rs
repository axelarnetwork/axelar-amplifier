use cosmwasm_schema::cw_serde;
use std::ops::Deref;

use crate::nonempty::Error;

#[cw_serde]
#[derive(Eq, Hash)]
pub struct HexBinary(cosmwasm_std::HexBinary);

impl TryFrom<cosmwasm_std::HexBinary> for HexBinary {
    type Error = Error;

    fn try_from(value: cosmwasm_std::HexBinary) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Error::InvalidValue("empty".to_string()))
        } else {
            Ok(HexBinary(value))
        }
    }
}

impl TryFrom<&[u8]> for HexBinary {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        HexBinary::try_from(cosmwasm_std::HexBinary::from(value))
    }
}

impl From<HexBinary> for cosmwasm_std::HexBinary {
    fn from(value: HexBinary) -> Self {
        value.0
    }
}

impl Deref for HexBinary {
    type Target = cosmwasm_std::HexBinary;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::nonempty::{Error, HexBinary};

    #[test]
    fn test_non_empty_hexbinary() {
        assert!(HexBinary::try_from(cosmwasm_std::HexBinary::from(&[1, 2, 3])).is_ok())
    }

    #[test]
    fn test_empty_non_empty_hexbinary() {
        assert_eq!(
            HexBinary::try_from(cosmwasm_std::HexBinary::from(&[])).unwrap_err(),
            Error::InvalidValue("empty".to_string())
        )
    }
}

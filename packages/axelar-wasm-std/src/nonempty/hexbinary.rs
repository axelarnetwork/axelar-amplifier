use std::ops::Deref;

use cosmwasm_schema::cw_serde;

use crate::nonempty::Error;

#[cw_serde]
#[serde(try_from = "cosmwasm_std::HexBinary")]
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

impl TryFrom<std::vec::Vec<u8>> for HexBinary {
    type Error = Error;

    fn try_from(value: std::vec::Vec<u8>) -> Result<Self, Self::Error> {
        cosmwasm_std::HexBinary::from(value).try_into()
    }
}

impl From<HexBinary> for cosmwasm_std::HexBinary {
    fn from(value: HexBinary) -> Self {
        value.0
    }
}

impl From<HexBinary> for std::vec::Vec<u8> {
    fn from(value: HexBinary) -> Self {
        value.0.into()
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
    use assert_ok::assert_ok;

    use crate::nonempty::{Error, HexBinary};

    #[test]
    fn test_non_empty_hexbinary() {
        assert_ok!(HexBinary::try_from(cosmwasm_std::HexBinary::from(&[
            1, 2, 3
        ])));
    }

    #[test]
    fn test_empty_non_empty_hexbinary() {
        assert_eq!(
            HexBinary::try_from(cosmwasm_std::HexBinary::from(&[])).unwrap_err(),
            Error::InvalidValue("empty".to_string())
        )
    }
}

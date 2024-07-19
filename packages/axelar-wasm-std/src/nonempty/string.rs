use std::ops::Deref;
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use valuable::Valuable;

use crate::nonempty::Error;

#[cw_serde]
#[serde(try_from = "std::string::String")]
#[derive(Eq, Hash, Valuable)]
pub struct String(std::string::String);

impl TryFrom<std::string::String> for String {
    type Error = Error;

    fn try_from(value: std::string::String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Error::InvalidValue("empty".to_string()))
        } else {
            Ok(String(value))
        }
    }
}

impl TryFrom<&str> for String {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        String::try_from(value.to_string())
    }
}

impl FromStr for String {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl From<String> for std::string::String {
    fn from(d: String) -> Self {
        d.0
    }
}

impl Deref for String {
    type Target = std::string::String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for crate::nonempty::Vec<u8> {
    fn from(value: String) -> Self {
        value.0.into_bytes().try_into().expect("cannot be empty")
    }
}

#[cfg(test)]
mod tests {
    use crate::nonempty;

    #[test]
    fn cannot_convert_from_empty_string() {
        assert!(nonempty::String::try_from("").is_err());
        assert!(serde_json::from_str::<nonempty::String>("\"\"").is_err());

        assert!(nonempty::String::try_from("some string").is_ok());
        assert!(serde_json::from_str::<nonempty::String>("\"some string\"").is_ok());
    }
}

use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use into_inner_derive::IntoInner;
use valuable::Valuable;

use crate::nonempty::Error;

#[cw_serde]
#[serde(try_from = "std::string::String")]
#[derive(Eq, Hash, Valuable, IntoInner)]
pub struct String(std::string::String);

impl String {
    pub const fn is_not_empty(value: &str) -> bool {
        !value.is_empty()
    }
}

impl PartialEq<&str> for &String {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<&str> for String {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

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

impl From<Addr> for String {
    fn from(value: Addr) -> Self {
        // valid address can never be empty
        Self(value.into_string())
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

impl Display for String {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[macro_export]
macro_rules! nonempty_str {
    ($s: literal) => {{
        use std::str::FromStr;
        const _: () = {
            if $s.is_empty() {
                panic!("string literal must not be empty");
            }
        };

        $crate::nonempty::String::from_str($s).expect("nonempty string was already checked")
    }};
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::nonempty;

    #[test]
    fn cannot_convert_from_empty_string() {
        assert!(nonempty::String::try_from("").is_err());
        assert!(serde_json::from_str::<nonempty::String>("\"\"").is_err());

        assert!(nonempty::String::try_from("some string").is_ok());
        assert!(serde_json::from_str::<nonempty::String>("\"some string\"").is_ok());
    }

    #[test]
    fn nonempty_str_macro_compiles() {
        assert_eq!(
            nonempty_str!("hello world"),
            nonempty::String::from_str("hello world").unwrap()
        );
    }
}

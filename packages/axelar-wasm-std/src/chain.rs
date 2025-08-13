use std::fmt;
use std::fmt::Display;
use std::str::FromStr;

use const_str::contains;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{StdError, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, Prefixer, PrimaryKey};
use error_stack::report;
use valuable::Valuable;

use crate::{FnExt, FIELD_DELIMITER};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("chain name is invalid")]
    InvalidChainName,
}

impl From<Error> for crate::error::ContractError {
    fn from(error: Error) -> Self {
        report!(error).into()
    }
}

/// ChainName represents the identifier used for chains in Amplifier.
/// Certain restrictions apply on the string:
/// - Must not be empty
/// - Must not exceed `ChainName::MAX_LEN` bytes
/// - Only ASCII characters are allowed
/// - Must not contain the `FIELD_DELIMITER` character
/// - The string is lowercased
#[cw_serde]
#[serde(try_from = "String")]
#[derive(Eq, Hash, Valuable)]
pub struct ChainName(String);

impl FromStr for ChainName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let chain_name: ChainNameRaw = s.parse()?;

        Ok(chain_name.normalize())
    }
}

#[macro_export]
macro_rules! chain_name {
    ($s: literal) => {{
        use std::str::FromStr;

        const _: () = {
            if !$crate::chain::ChainNameRaw::is_raw_chain_name($s) {
                panic!("string literal is not a valid chain name");
            }
        };

        $crate::chain::ChainName::from_str($s).expect("string literal was already checked")
    }};
}

impl From<ChainName> for String {
    fn from(d: ChainName) -> Self {
        d.0
    }
}

impl TryFrom<String> for ChainName {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<&str> for ChainName {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Display for ChainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<ChainNameRaw> for ChainName {
    fn eq(&self, other: &ChainNameRaw) -> bool {
        self == &other.as_ref()
    }
}

impl PartialEq<String> for ChainName {
    fn eq(&self, other: &String) -> bool {
        self == &other.as_str()
    }
}

impl PartialEq<&str> for ChainName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PrimaryKey<'_> for ChainName {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl Prefixer<'_> for ChainName {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl KeyDeserialize for ChainName {
    type Output = Self;
    const KEY_ELEMS: u16 = 1;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        String::from_utf8(value)
            .map_err(StdError::invalid_utf8)?
            .then(ChainName::try_from)
            .map_err(StdError::invalid_utf8)
    }
}

impl KeyDeserialize for &ChainName {
    type Output = ChainName;
    const KEY_ELEMS: u16 = 1;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        ChainName::from_vec(value)
    }
}

impl AsRef<str> for ChainName {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

/// ChainNameRaw represents the raw case-sensitive identifier used for source chains in Amplifier.
/// It is backwards compatible with case-sensitive chain names used in axelar-core (e.g. `Ethereum`).
///
/// Certain restrictions apply on the string:
/// - Must not be empty
/// - Must not exceed `ChainNameRaw::MAX_LEN` bytes
/// - Only ASCII characters are allowed
/// - Must not contain the `FIELD_DELIMITER` character
/// - Case-sensitivity is preserved
#[cw_serde]
#[serde(try_from = "String")]
#[derive(Eq, Hash)]
pub struct ChainNameRaw(String);

impl From<ChainName> for ChainNameRaw {
    fn from(other: ChainName) -> Self {
        ChainNameRaw(other.0)
    }
}

impl ChainNameRaw {
    /// Maximum length of a chain name (in bytes).
    /// This MUST NOT be changed without a corresponding change to the ChainName validation in axelar-core.
    const MAX_LEN: usize = 20;

    /// Special care must be taken when using this function. Normalization means a loss of information
    /// and can lead to the chain not being found in the database. This function should only be used if absolutely necessary.
    pub fn normalize(&self) -> ChainName {
        ChainName(self.as_ref().to_lowercase())
    }

    pub const fn is_raw_chain_name(s: &str) -> bool {
        !s.is_empty() && s.len() <= Self::MAX_LEN && s.is_ascii() && !contains!(s, FIELD_DELIMITER)
    }
}

impl FromStr for ChainNameRaw {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !Self::is_raw_chain_name(s) {
            return Err(Error::InvalidChainName);
        }

        Ok(ChainNameRaw(s.to_owned()))
    }
}

#[macro_export]
macro_rules! chain_name_raw {
    ($s:literal) => {{
        use std::str::FromStr as _;

        const _: () = {
            if !$crate::chain::ChainNameRaw::is_raw_chain_name($s) {
                panic!("string literal is not a valid chain name");
            }
        };

        $crate::chain::ChainNameRaw::from_str($s).expect("string literal was already checked")
    }};
}

impl From<ChainNameRaw> for String {
    fn from(d: ChainNameRaw) -> Self {
        d.0
    }
}

impl TryFrom<String> for ChainNameRaw {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl TryFrom<&str> for ChainNameRaw {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Display for ChainNameRaw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for ChainNameRaw {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl PartialEq<ChainName> for ChainNameRaw {
    fn eq(&self, other: &ChainName) -> bool {
        self == &other.as_ref()
    }
}

impl PartialEq<String> for ChainNameRaw {
    fn eq(&self, other: &String) -> bool {
        self == &other.as_str()
    }
}

impl PartialEq<&str> for ChainNameRaw {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PrimaryKey<'_> for ChainNameRaw {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl Prefixer<'_> for ChainNameRaw {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl KeyDeserialize for ChainNameRaw {
    type Output = Self;
    const KEY_ELEMS: u16 = 1;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        String::from_utf8(value)
            .map_err(StdError::invalid_utf8)?
            .then(ChainNameRaw::try_from)
            .map_err(StdError::invalid_utf8)
    }
}

impl KeyDeserialize for &ChainNameRaw {
    type Output = ChainNameRaw;
    const KEY_ELEMS: u16 = 1;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        ChainNameRaw::from_vec(value)
    }
}

#[cfg(test)]
mod tests {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn should_not_deserialize_invalid_chain_name() {
        assert_eq!(
            "chain name is invalid",
            serde_json::from_str::<ChainName>("\"\"")
                .unwrap_err()
                .to_string()
        );

        assert_eq!(
            "chain name is invalid",
            serde_json::from_str::<ChainName>(format!("\"chain{FIELD_DELIMITER}\"").as_str())
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn ensure_chain_name_parsing_respect_restrictions() {
        struct TestCase<'a> {
            input: &'a str,
            can_parse: bool,
            is_normalized: bool,
        }
        let random_lower = random_chain_name().to_lowercase();
        let random_upper = random_chain_name().to_uppercase();

        let test_cases = [
            TestCase {
                input: "",
                can_parse: false,
                is_normalized: false,
            },
            TestCase {
                input: "chain_with_prohibited_symbols",
                can_parse: false,
                is_normalized: false,
            },
            TestCase {
                input: "!@#$%^&*()+=-",
                can_parse: true,
                is_normalized: true,
            },
            TestCase {
                input: "1234567890",
                can_parse: true,
                is_normalized: true,
            },
            TestCase {
                input: "ethereum",
                can_parse: true,
                is_normalized: true,
            },
            TestCase {
                input: "ETHEREUM",
                can_parse: true,
                is_normalized: false,
            },
            TestCase {
                input: "ethereum-1",
                can_parse: true,
                is_normalized: true,
            },
            TestCase {
                input: "ETHEREUM-1",
                can_parse: true,
                is_normalized: false,
            },
            TestCase {
                input: "long chain name over max len",
                can_parse: false,
                is_normalized: false,
            },
            TestCase {
                input: "UTF-8 ❤",
                can_parse: false,
                is_normalized: false,
            },
            TestCase {
                input: random_lower.as_str(),
                can_parse: true,
                is_normalized: true,
            },
            TestCase {
                input: random_upper.as_str(),
                can_parse: true,
                is_normalized: false,
            },
        ];

        let conversions = [
            |input: &str| ChainName::from_str(input),
            |input: &str| ChainName::try_from(input),
            |input: &str| ChainName::try_from(input.to_string()),
        ];

        let raw_conversions = [
            |input: &str| ChainNameRaw::from_str(input),
            |input: &str| ChainNameRaw::try_from(input),
            |input: &str| ChainNameRaw::try_from(input.to_string()),
        ];

        for case in test_cases.into_iter() {
            for conversion in conversions.into_iter() {
                let result = conversion(case.input);
                assert_eq!(result.is_ok(), case.can_parse, "input: {}", case.input);
                if case.can_parse {
                    if case.is_normalized {
                        assert_eq!(result.unwrap(), case.input);
                    } else {
                        assert_ne!(result.unwrap(), case.input);
                    }
                }
            }

            for conversion in raw_conversions.into_iter() {
                let result = conversion(case.input);
                assert_eq!(result.is_ok(), case.can_parse, "input: {}", case.input);
                if case.can_parse {
                    assert_eq!(result.unwrap(), case.input);
                }
            }
        }
    }

    #[test]
    fn chain_name_macros_compile() {
        assert_eq!(
            chain_name_raw!("ETHEREUM-1"),
            ChainNameRaw::from_str("ETHEREUM-1").unwrap()
        );
        assert_eq!(
            chain_name!("ETHEREUM-1"),
            ChainName::from_str("ETHEREUM-1").unwrap()
        );
    }

    fn random_chain_name() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect()
    }
}

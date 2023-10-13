use crate::error::*;
use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_schema::serde::{Deserialize, Serialize};
use error_stack::{Report, ResultExt};
use flagset::flags;
use regex::Regex;
use schemars::JsonSchema;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::ops::Deref;
use std::str::FromStr;

#[cw_serde]
pub struct Message {
    /// This field can hold arbitrary data. It has only two requirements:
    /// 1. it must be possible to use its content to find the corresponding message on the source chain
    /// 2. the ID must uniquely identify the message on the source chain, i.e. no two messages can have the same ID, and no single message can have multiple valid IDs.
    ///
    /// IMPORTANT: Verifier contracts must enforce these requirements.
    pub id: String,
    pub source_chain: ChainName,
    pub source_address: Address,
    pub destination_chain: ChainName,
    pub destination_address: Address,
    /// hash length is enforced to be 32 bytes
    pub payload_hash: [u8; 32],
}

// [cw_serde] has been expanded here because we need to implement PartialEq manually
#[derive(
    ::cosmwasm_schema::serde::Serialize,
    ::cosmwasm_schema::serde::Deserialize,
    Clone,
    Debug,
    ::cosmwasm_schema::schemars::JsonSchema,
)]
#[serde(deny_unknown_fields, crate = "::cosmwasm_schema::serde")]
#[schemars(crate = "::cosmwasm_schema::schemars")]
#[serde(try_from = "String")]
pub struct ChainName(String);

impl Hash for ChainName {
    /// this is implemented manually because we want to ignore case when hashing
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_lowercase().hash(state)
    }
}

impl PartialEq for ChainName {
    /// this is implemented manually because we want to ignore case when checking equality
    fn eq(&self, other: &Self) -> bool {
        self.0.to_lowercase() == other.0.to_lowercase()
    }
}

impl FromStr for ChainName {
    type Err = Error;

    fn from_str(chain_name: &str) -> Result<Self, Self::Err> {
        let is_chain_name_valid = Regex::new(CHAIN_NAME_REGEX)
            .expect("invalid regex pattern for chain name")
            .is_match(chain_name);

        if is_chain_name_valid {
            Ok(ChainName(chain_name.to_string()))
        } else {
            Err(Error::ChainNamePatternMismatch(chain_name.to_string()))
        }
    }
}

impl TryFrom<String> for ChainName {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Display for ChainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[cw_serde]
pub struct Address(nonempty::String);

impl FromStr for Address {
    type Err = Report<Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<nonempty::String>()
            .change_context(Error::EmptyAddress)
            .map(Address)
    }
}
impl TryFrom<String> for Address {
    type Error = Report<Error>;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Deref for Address {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

flags! {
    #[repr(u8)]
    #[derive(Deserialize, Serialize, Hash, JsonSchema)]
    pub enum GatewayDirection: u8 {
        None = 0,
        Incoming = 1,
        Outgoing = 2,
        Bidirectional = (GatewayDirection::Incoming | GatewayDirection::Outgoing).bits(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::Hasher;

    #[test]
    fn chain_names_adhere_to_naming_scheme() {
        let test_cases = vec![
            ("Ethereum", true),
            ("ethereum", true),
            ("a", true),
            ("terra2", true),
            ("terra-2", true),
            ("", false),
            ("ETHEREUM", false),
            ("ethereuM", false),
            ("e2e", false),
            ("e:e", false),
            ("polygon-0-1", false),
        ];

        test_cases.into_iter().for_each(|(name, is_match)| {
            assert_eq!(
                name.parse::<ChainName>().is_ok(),
                is_match,
                "mismatch for {}",
                name
            );
        });
    }

    #[test]
    fn chain_name_equality_is_case_insensitive() {
        let chain_name_1 = "Ethereum".parse::<ChainName>().unwrap();
        let chain_name_2 = "ethereum".parse::<ChainName>().unwrap();
        assert_eq!(chain_name_1, chain_name_2);
    }

    #[test]
    fn chain_name_hash_is_case_insensitive() {
        let mut hasher_1 = DefaultHasher::new();
        let chain_name_1 = "Ethereum".parse::<ChainName>().unwrap();
        chain_name_1.hash(&mut hasher_1);
        let hash_1 = hasher_1.finish();

        let mut hasher_2 = DefaultHasher::new();
        let chain_name_2 = "ethereum".parse::<ChainName>().unwrap();
        chain_name_2.hash(&mut hasher_2);
        let hash_2 = hasher_2.finish();

        assert_eq!(hash_1, hash_2);
    }

    #[test]
    fn address_cannot_be_empty() {
        assert!("".parse::<Address>().is_err());
        assert!("some_address".parse::<Address>().is_ok());
    }
}

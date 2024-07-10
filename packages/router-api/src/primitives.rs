use axelar_wasm_std::flagset::FlagSet;
use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::{hash::Hash, nonempty, FnExt};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Attribute, HexBinary};
use cosmwasm_std::{StdError, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, Prefixer, PrimaryKey};
use error_stack::Report;
use error_stack::ResultExt;
use flagset::flags;
use schemars::gen::SchemaGenerator;
use schemars::schema::Schema;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::fmt::{Debug, Display};
use std::{any::type_name, fmt, ops::Deref, str::FromStr};
use valuable::Valuable;

use crate::error::*;

pub const CHAIN_NAME_DELIMITER: char = '_';

#[cw_serde]
#[derive(Eq, Hash)]
pub struct Message {
    pub cc_id: CrossChainId,
    pub source_address: Address,
    pub destination_chain: GeneralizedChainName,
    pub destination_address: Address,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce its format.
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub payload_hash: [u8; 32],
}

impl Message {
    pub fn hash(&self) -> Hash {
        let mut hasher = Keccak256::new();
        hasher.update(self.cc_id.to_string());
        hasher.update(self.source_address.as_str());
        hasher.update(self.destination_chain.as_ref());
        hasher.update(self.destination_address.as_str());
        hasher.update(self.payload_hash);
        hasher.finalize().into()
    }
}

impl From<Message> for Vec<Attribute> {
    fn from(other: Message) -> Self {
        vec![
            ("id", other.cc_id.id).into(),
            ("source_chain", other.cc_id.chain).into(),
            ("source_address", other.source_address.deref()).into(),
            ("destination_chain", other.destination_chain).into(),
            ("destination_address", other.destination_address.deref()).into(),
            (
                "payload_hash",
                HexBinary::from(other.payload_hash).to_string(),
            )
                .into(),
        ]
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct Address(nonempty::String);

impl Deref for Address {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl FromStr for Address {
    type Err = Report<Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::try_from(s.to_string())
    }
}

impl TryFrom<String> for Address {
    type Error = Report<Error>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Address(
            value
                .parse::<nonempty::String>()
                .change_context(Error::InvalidAddress)?,
        ))
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct CrossChainId {
    pub chain: GeneralizedChainName,
    pub id: nonempty::String,
}

impl Display for CrossChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", self.chain, CHAIN_NAME_DELIMITER, *self.id)
    }
}

impl PrimaryKey<'_> for CrossChainId {
    type Prefix = GeneralizedChainName;
    type SubPrefix = ();
    type Suffix = String;
    type SuperSuffix = (GeneralizedChainName, String);

    fn key(&self) -> Vec<Key> {
        let mut keys = self.chain.key();
        keys.extend(self.id.key());
        keys
    }
}

impl KeyDeserialize for CrossChainId {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let (chain, id) = <(GeneralizedChainName, String)>::from_vec(value)?;
        Ok(CrossChainId {
            chain,
            id: id
                .try_into()
                .map_err(|err| StdError::parse_err(type_name::<nonempty::String>(), err))?,
        })
    }
}

#[cw_serde]
#[serde(try_from = "String")]
#[derive(Eq, Hash, Valuable)]
pub struct ChainName(String);

impl FromStr for ChainName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(CHAIN_NAME_DELIMITER) || s.is_empty() || s.chars().any(char::is_uppercase) {
            return Err(Error::InvalidChainName);
        }

        Ok(ChainName(s.to_owned()))
    }
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

impl Display for ChainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<String> for ChainName {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

impl<'a> PrimaryKey<'a> for ChainName {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl<'a> Prefixer<'a> for ChainName {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl KeyDeserialize for ChainName {
    type Output = Self;

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

#[cw_serde]
#[serde(try_from = "String")]
#[derive(Eq, Hash)]
pub struct LegacyChainName(String);

impl FromStr for LegacyChainName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(CHAIN_NAME_DELIMITER) || s.is_empty() {
            return Err(Error::InvalidChainName);
        }

        Ok(LegacyChainName(s.to_owned()))
    }
}

impl From<LegacyChainName> for String {
    fn from(d: LegacyChainName) -> Self {
        d.0
    }
}

impl TryFrom<String> for LegacyChainName {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Display for LegacyChainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for LegacyChainName {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl<'a> PrimaryKey<'a> for LegacyChainName {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl<'a> Prefixer<'a> for LegacyChainName {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl KeyDeserialize for LegacyChainName {
    type Output = Self;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        String::from_utf8(value)
            .map_err(StdError::invalid_utf8)?
            .then(LegacyChainName::try_from)
            .map_err(StdError::invalid_utf8)
    }
}

impl KeyDeserialize for &LegacyChainName {
    type Output = ChainName;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        ChainName::from_vec(value)
    }
}

#[cw_serde]
#[serde(try_from = "String", into = "String")]
#[derive(Eq, Hash)]
pub enum GeneralizedChainName {
    Amplifier(ChainName),
    Legacy(LegacyChainName),
}

impl GeneralizedChainName {
    pub fn amplifier(self) -> Result<ChainName, Error> {
        match self {
            GeneralizedChainName::Amplifier(chain) => Ok(chain),
            GeneralizedChainName::Legacy(_) => Err(Error::InvalidChainName),
        }
    }

    pub fn legacy(self) -> Result<LegacyChainName, Error> {
        match self {
            GeneralizedChainName::Amplifier(_) => Err(Error::InvalidChainName),
            GeneralizedChainName::Legacy(chain) => Ok(chain),
        }
    }
}

impl AsRef<str> for GeneralizedChainName {
    fn as_ref(&self) -> &str {
        match self {
            GeneralizedChainName::Amplifier(chain) => chain.as_ref(),
            GeneralizedChainName::Legacy(chain) => chain.as_ref(),
        }
    }
}

impl FromStr for GeneralizedChainName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ChainName::from_str(s).map_or_else(
            |_| Ok(GeneralizedChainName::Legacy(LegacyChainName::from_str(s)?)),
            |chain| Ok(GeneralizedChainName::Amplifier(chain)),
        )
    }
}

impl TryFrom<String> for GeneralizedChainName {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<GeneralizedChainName> for String {
    fn from(d: GeneralizedChainName) -> Self {
        match d {
            GeneralizedChainName::Amplifier(chain) => chain.into(),
            GeneralizedChainName::Legacy(chain) => chain.into(),
        }
    }
}

impl Display for GeneralizedChainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeneralizedChainName::Amplifier(chain) => Display::fmt(chain, f),
            GeneralizedChainName::Legacy(chain) => Display::fmt(chain, f),
        }
    }
}

impl PartialEq<ChainName> for GeneralizedChainName {
    fn eq(&self, other: &ChainName) -> bool {
        match self {
            GeneralizedChainName::Amplifier(chain) => chain.eq(other),
            GeneralizedChainName::Legacy(_) => false,
        }
    }
}

impl PartialEq<LegacyChainName> for GeneralizedChainName {
    fn eq(&self, other: &LegacyChainName) -> bool {
        match self {
            GeneralizedChainName::Amplifier(_) => false,
            GeneralizedChainName::Legacy(chain) => chain.eq(other),
        }
    }
}

impl<'a> PrimaryKey<'a> for GeneralizedChainName {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        match self {
            GeneralizedChainName::Amplifier(chain) => chain.key(),
            GeneralizedChainName::Legacy(chain) => chain.key(),
        }
    }
}

impl<'a> Prefixer<'a> for GeneralizedChainName {
    fn prefix(&self) -> Vec<Key> {
        match self {
            GeneralizedChainName::Amplifier(chain) => chain.prefix(),
            GeneralizedChainName::Legacy(chain) => chain.prefix(),
        }
    }
}

impl KeyDeserialize for GeneralizedChainName {
    type Output = Self;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        String::from_utf8(value)
            .map_err(StdError::invalid_utf8)?
            .then(GeneralizedChainName::try_from)
            .map_err(StdError::invalid_utf8)
    }
}

impl KeyDeserialize for &GeneralizedChainName {
    type Output = ChainName;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        ChainName::from_vec(value)
    }
}

flags! {
    #[repr(u8)]
    #[derive(Deserialize, Serialize, Hash)]
    pub enum GatewayDirection: u8 {
        None = 0,
        Incoming = 1,
        Outgoing = 2,
        Bidirectional = (GatewayDirection::Incoming | GatewayDirection::Outgoing).bits(),
    }
}

impl JsonSchema for GatewayDirection {
    fn schema_name() -> String {
        "GatewayDirection".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        gen.subschema_for::<u8>()
    }
}

#[cw_serde]
pub struct Gateway {
    pub address: Addr,
}

#[cw_serde]
pub struct ChainEndpoint {
    pub name: ChainName,
    pub gateway: Gateway,
    pub frozen_status: FlagSet<GatewayDirection>,
    pub msg_id_format: MessageIdFormat,
}

impl ChainEndpoint {
    pub fn incoming_frozen(&self) -> bool {
        self.frozen_status.contains(GatewayDirection::Incoming)
    }

    pub fn outgoing_frozen(&self) -> bool {
        self.frozen_status.contains(GatewayDirection::Outgoing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::to_json_vec;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use sha3::{Digest, Sha3_256};

    #[test]
    // Any modifications to the Message struct fields or their types
    // will cause this test to fail, indicating that a migration is needed.
    fn test_message_struct_unchanged() {
        let expected_message_hash =
            "e8052da3a89c90468cc6e4e242a827f8579fb0ea8e298b1650d73a0f7e81abc3";

        let msg = dummy_message();

        assert_eq!(
            hex::encode(Sha3_256::digest(to_json_vec(&msg).unwrap())),
            expected_message_hash
        );
    }

    // If this test fails, it means the message hash has changed and therefore a migration is needed.
    #[test]
    fn hash_id_unchanged() {
        let expected_message_hash =
            "d30a374a795454706b43259998aafa741267ecbc8b6d5771be8d7b8c9a9db263";

        let msg = dummy_message();

        assert_eq!(hex::encode(msg.hash()), expected_message_hash);
    }

    #[test]
    fn should_fail_to_parse_invalid_chain_name() {
        // empty
        assert_eq!(
            "".parse::<ChainName>().unwrap_err(),
            Error::InvalidChainName
        );

        // name contains id separator
        assert_eq!(
            format!("chain {CHAIN_NAME_DELIMITER}")
                .parse::<ChainName>()
                .unwrap_err(),
            Error::InvalidChainName
        );
    }

    #[test]
    fn should_parse_to_case_insensitive_chain_name() {
        let rand_str: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        let chain_name: ChainName = rand_str.parse().unwrap();

        assert_eq!(
            chain_name,
            rand_str.to_lowercase().parse::<ChainName>().unwrap()
        );
        assert_eq!(
            chain_name,
            rand_str.to_uppercase().parse::<ChainName>().unwrap()
        );
    }

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
            serde_json::from_str::<ChainName>(format!("\"chain{CHAIN_NAME_DELIMITER}\"").as_str())
                .unwrap_err()
                .to_string()
        );
    }

    // #[test]
    // fn chain_name_case_insensitive_comparison() {
    //     let chain_name = ChainName::from_str("ethereum").unwrap();
    //
    //     assert!(chain_name.eq(&"Ethereum".to_string()));
    //     assert!(chain_name.eq(&"ETHEREUM".to_string()));
    //     assert!(chain_name.eq(&"ethereum".to_string()));
    //     assert!(chain_name.eq(&"ethEReum".to_string()));
    //
    //     assert!(!chain_name.eq(&"Ethereum-1".to_string()));
    // }

    #[test]
    fn json_schema_for_gateway_direction_flag_set_does_not_panic() {
        let gen = &mut SchemaGenerator::default();
        // check it doesn't panic
        let _ = FlagSet::<GatewayDirection>::json_schema(gen);

        // make sure it's the same as the underlying type
        assert_eq!(GatewayDirection::json_schema(gen), u8::json_schema(gen));
    }

    fn dummy_message() -> Message {
        Message {
            cc_id: CrossChainId {
                id: "hash-index".parse().unwrap(),
                chain: "chain".parse().unwrap(),
            },
            source_address: "source_address".parse().unwrap(),
            destination_chain: "destination-chain".parse().unwrap(),
            destination_address: "destination_address".parse().unwrap(),
            payload_hash: [1; 32],
        }
    }
}

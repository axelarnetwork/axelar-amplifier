use std::any::type_name;
use std::fmt;
use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;

use axelar_wasm_std::flagset::FlagSet;
use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::{nonempty, FnExt};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Attribute, HexBinary, StdError, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, Prefixer, PrimaryKey};
use error_stack::{Context, Report, ResultExt};
use flagset::flags;
use schemars::gen::SchemaGenerator;
use schemars::schema::Schema;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use valuable::Valuable;

use crate::error::*;

/// Delimiter used when concatenating fields to prevent ambiguous encodings.
/// The delimiter must be prevented from being contained in values that are used as fields.
pub const FIELD_DELIMITER: char = '_';

#[cw_serde]
#[derive(Eq, Hash)]
pub struct Message {
    pub cc_id: CrossChainId,
    pub source_address: Address,
    pub destination_chain: ChainName,
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
        let delimiter_bytes = &[FIELD_DELIMITER as u8];

        hasher.update(self.cc_id.to_string());
        hasher.update(delimiter_bytes);
        hasher.update(self.source_address.as_str());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_chain.as_ref());
        hasher.update(delimiter_bytes);
        hasher.update(self.destination_address.as_str());
        hasher.update(delimiter_bytes);
        hasher.update(self.payload_hash);

        hasher.finalize().into()
    }
}

impl From<Message> for Vec<Attribute> {
    fn from(other: Message) -> Self {
        vec![
            ("message_id", other.cc_id.message_id).into(),
            ("source_chain", other.cc_id.source_chain).into(),
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
#[serde(try_from = "String")]
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
        if value.contains(FIELD_DELIMITER) {
            return Err(Report::new(Error::InvalidAddress));
        }

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
    pub source_chain: ChainNameRaw,
    pub message_id: nonempty::String,
}

impl CrossChainId {
    pub fn new<S, T>(
        chain: impl TryInto<ChainNameRaw, Error = S>,
        id: impl TryInto<nonempty::String, Error = T>,
    ) -> error_stack::Result<Self, Error>
    where
        S: Context,
        T: Context,
    {
        Ok(CrossChainId {
            source_chain: chain.try_into().change_context(Error::InvalidChainName)?,
            message_id: id.try_into().change_context(Error::InvalidMessageId)?,
        })
    }
}

impl PrimaryKey<'_> for CrossChainId {
    type Prefix = ChainNameRaw;
    type SubPrefix = ();
    type Suffix = String;
    type SuperSuffix = (ChainNameRaw, String);

    fn key(&self) -> Vec<Key> {
        let mut keys = self.source_chain.key();
        keys.extend(self.message_id.key());
        keys
    }
}

impl KeyDeserialize for CrossChainId {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let (source_chain, id) = <(ChainNameRaw, String)>::from_vec(value)?;
        Ok(CrossChainId {
            source_chain,
            message_id: id
                .try_into()
                .map_err(|err| StdError::parse_err(type_name::<nonempty::String>(), err))?,
        })
    }
}
impl Display for CrossChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            self.source_chain, FIELD_DELIMITER, *self.message_id
        )
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

        Ok(ChainName(chain_name.0.to_lowercase()))
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
}

impl FromStr for ChainNameRaw {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > Self::MAX_LEN || !s.is_ascii() || s.contains(FIELD_DELIMITER) {
            return Err(Error::InvalidChainName);
        }

        Ok(ChainNameRaw(s.to_owned()))
    }
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

impl<'a> PrimaryKey<'a> for ChainNameRaw {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl<'a> Prefixer<'a> for ChainNameRaw {
    fn prefix(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl KeyDeserialize for ChainNameRaw {
    type Output = Self;

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

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        ChainNameRaw::from_vec(value)
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
    use cosmwasm_std::to_json_vec;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use sha3::{Digest, Sha3_256};

    use super::*;

    #[test]
    // Any modifications to the Message struct fields or their types
    // will cause this test to fail, indicating that a migration is needed.
    fn test_message_struct_unchanged() {
        let expected_message_hash =
            "3a0edbeb590d12cf9f71864469d9e7afd52cccf2798db09c55def296af3a8e89";

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
            "e6b9cc9b6962c997b44ded605ebfb4f861e2db2ddff7e8be84a7a79728cea61e";

        let msg = dummy_message();

        assert_eq!(hex::encode(msg.hash()), expected_message_hash);
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
    fn should_not_deserialize_invalid_address() {
        assert_eq!(
            "address is invalid",
            serde_json::from_str::<Address>("\"\"")
                .unwrap_err()
                .to_string()
        );

        assert_eq!(
            "address is invalid",
            serde_json::from_str::<Address>(format!("\"address{FIELD_DELIMITER}\"").as_str())
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn ensure_address_parsing_respect_restrictions() {
        struct TestCase<'a> {
            input: &'a str,
            can_parse: bool,
        }
        let random_lower = random_address().to_lowercase();
        let random_upper = random_address().to_uppercase();

        let test_cases = [
            TestCase {
                input: "",
                can_parse: false,
            },
            TestCase {
                input: "address_with_prohibited_symbols",
                can_parse: false,
            },
            TestCase {
                input: "!@#$%^&*()+=-1234567890",
                can_parse: true,
            },
            TestCase {
                input: "0x4F4495243837681061C4743b74B3eEdf548D56A5",
                can_parse: true,
            },
            TestCase {
                input: "0x4f4495243837681061c4743b74b3eedf548d56a5",
                can_parse: true,
            },
            TestCase {
                input: "GARRAOPAA5MNY3Y5V2OOYXUMBC54UDHHJTUMLRQBY2DIZKT62G5WSJP4Copy",
                can_parse: true,
            },
            TestCase {
                input: "ETHEREUM-1",
                can_parse: true,
            },
            TestCase {
                input: random_lower.as_str(),
                can_parse: true,
            },
            TestCase {
                input: random_upper.as_str(),
                can_parse: true,
            },
        ];

        let conversions: [fn(&str) -> Result<Address, _>; 2] = [
            |input: &str| Address::from_str(input),
            |input: &str| Address::try_from(input.to_string()),
        ];

        for case in test_cases.into_iter() {
            for conversion in conversions.into_iter() {
                let result = conversion(case.input);
                assert_eq!(result.is_ok(), case.can_parse, "input: {}", case.input);
                if case.can_parse {
                    assert_eq!(result.unwrap().to_string(), case.input);
                }
            }
        }
    }

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
            cc_id: CrossChainId::new("chain", "hash-index").unwrap(),
            source_address: "source-address".parse().unwrap(),
            destination_chain: "destination-chain".parse().unwrap(),
            destination_address: "destination-address".parse().unwrap(),
            payload_hash: [1; 32],
        }
    }

    fn random_chain_name() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect()
    }

    fn random_address() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect()
    }
}

use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, StdResult};
use cw_storage_plus::{Key, KeyDeserialize, Prefixer, PrimaryKey};
use flagset::flags;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use axelar_wasm_std::flagset::FlagSet;
use axelar_wasm_std::FnExt;

use crate::ContractError;

pub const ID_SEPARATOR: char = ':';

#[cw_serde]
#[serde(try_from = "String")]
pub struct MessageID(String);

impl FromStr for MessageID {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // todo: should split in exactly 2 parts when migrated to state::NewMessage
        let split: Vec<_> = s.split(ID_SEPARATOR).filter(|s| !s.is_empty()).collect();
        if split.len() < 2 {
            return Err(ContractError::InvalidMessageID);
        }
        Ok(MessageID(s.to_lowercase()))
    }
}

impl TryFrom<String> for MessageID {
    type Error = ContractError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().parse()
    }
}

impl From<MessageID> for String {
    fn from(d: MessageID) -> Self {
        d.0
    }
}

impl Deref for MessageID {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for MessageID {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> PrimaryKey<'a> for MessageID {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl KeyDeserialize for MessageID {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self> {
        let value = String::from_utf8(value).map_err(StdError::invalid_utf8)?;
        Ok(Self(value))
    }
}

/// cosmwasm cannot serialize tuples, so we need to convert [CrossChainUid] into a struct
#[cw_serde]
pub struct CrossChainUid {
    pub chain: ChainName,
    pub id: MessageID,
}

impl Display for CrossChainUid {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", &self.chain, ID_SEPARATOR, &self.id)
    }
}

impl PrimaryKey<'_> for CrossChainUid {
    type Prefix = ChainName;
    type SubPrefix = ();
    type Suffix = MessageID;
    type SuperSuffix = (ChainName, MessageID);

    fn key(&self) -> Vec<Key> {
        let mut keys = self.chain.key();
        keys.extend(self.id.key());
        keys
    }
}

impl KeyDeserialize for CrossChainUid {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let (chain, id) = <(ChainName, MessageID)>::from_vec(value)?;
        Ok(CrossChainUid { chain, id })
    }
}

#[cw_serde]
#[serde(try_from = "String")]
pub struct ChainName(String);

impl FromStr for ChainName {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains(ID_SEPARATOR) || s.is_empty() {
            return Err(ContractError::InvalidChainName);
        }

        Ok(ChainName(s.to_lowercase()))
    }
}

impl From<ChainName> for String {
    fn from(d: ChainName) -> Self {
        d.0
    }
}

impl TryFrom<String> for ChainName {
    type Error = ContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Display for ChainName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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

#[cw_serde]
pub struct Gateway {
    pub address: Addr,
}

#[cw_serde]
pub struct ChainEndpoint {
    pub name: ChainName,
    pub gateway: Gateway,
    pub frozen_status: FlagSet<GatewayDirection>,
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
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    use super::*;

    #[test]
    fn should_fail_to_parse_invalid_chain_name() {
        // empty
        assert_eq!(
            "".parse::<ChainName>().unwrap_err(),
            ContractError::InvalidChainName
        );

        // name contains id separator
        assert_eq!(
            format!("chain {ID_SEPARATOR}")
                .parse::<ChainName>()
                .unwrap_err(),
            ContractError::InvalidChainName
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
            serde_json::from_str::<ChainName>(format!("\"\"").as_str())
                .unwrap_err()
                .to_string()
        );

        assert_eq!(
            "chain name is invalid",
            serde_json::from_str::<ChainName>(format!("\"chain{ID_SEPARATOR}\"").as_str())
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn message_id_must_have_at_least_one_separator() {
        assert!(MessageID::from_str("source_chain:hash:id").is_ok());
        assert!(serde_json::from_str::<MessageID>("\"source_chain:hash:id\"").is_ok());

        assert!(MessageID::from_str("invalid_hash").is_err());
        assert!(serde_json::from_str::<MessageID>("\"invalid_hash\"").is_err());

        assert!(MessageID::from_str("invalid_hash:").is_err());
    }

    #[test]
    fn message_id_is_lower_case() {
        let msg_id = "HaSH:iD".parse::<MessageID>().unwrap();
        assert_eq!(msg_id.to_string(), "hash:id");
    }

    #[test]
    fn serialize_global_message_id() {
        let id = CrossChainUid {
            chain: "ethereum".parse().unwrap(),
            id: "hash:id".parse().unwrap(),
        };

        let serialized = serde_json::to_string(&id).unwrap();
        assert_eq!(id, serde_json::from_str(&serialized).unwrap());
    }
}

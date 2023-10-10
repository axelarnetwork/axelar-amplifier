#![allow(deprecated)]

use core::panic;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, HexBinary, Order, StdError, StdResult};
use cw_storage_plus::{
    Index, IndexList, IndexedMap, Item, Key, KeyDeserialize, MultiIndex, Prefixer, PrimaryKey,
};
use error_stack::{Report, ResultExt};
use flagset::flags;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use axelar_wasm_std::flagset::FlagSet;
use axelar_wasm_std::{nonempty, FnExt};

use crate::ContractError;

pub const ID_SEPARATOR: char = ':';

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub governance: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

pub struct ChainEndpointIndexes<'a> {
    pub gateway: GatewayIndex<'a>,
}

pub struct GatewayIndex<'a>(MultiIndex<'a, Addr, ChainEndpoint, ChainName>);

impl<'a> GatewayIndex<'a> {
    pub fn new(
        idx_fn: fn(&[u8], &ChainEndpoint) -> Addr,
        pk_namespace: &'a str,
        idx_namespace: &'a str,
    ) -> Self {
        GatewayIndex(MultiIndex::new(idx_fn, pk_namespace, idx_namespace))
    }

    pub fn find_chain(
        &self,
        deps: &DepsMut,
        contract_address: &Addr,
    ) -> StdResult<Option<ChainEndpoint>> {
        let mut matching_chains = self
            .0
            .prefix(contract_address.clone())
            .range(deps.storage, None, None, Order::Ascending)
            .collect::<Result<Vec<_>, _>>()?;

        if matching_chains.len() > 1 {
            panic!("More than one gateway for chain")
        }

        Ok(matching_chains.pop().map(|(_, chain)| chain))
    }
}

const CHAINS_PKEY: &str = "chains";

pub fn chain_endpoints<'a>() -> IndexedMap<'a, ChainName, ChainEndpoint, ChainEndpointIndexes<'a>> {
    return IndexedMap::new(
        CHAINS_PKEY,
        ChainEndpointIndexes {
            gateway: GatewayIndex::new(
                |_pk: &[u8], d: &ChainEndpoint| d.gateway.address.clone(),
                CHAINS_PKEY,
                "gateways",
            ),
        },
    );
}

impl<'a> IndexList<ChainEndpoint> for ChainEndpointIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<ChainEndpoint>> + '_> {
        let v: Vec<&dyn Index<ChainEndpoint>> = vec![&self.gateway.0];
        Box::new(v.into_iter())
    }
}

#[cw_serde]
pub struct Message {
    pub cc_id: CrossChainId,
    pub destination_address: Address,
    pub destination_chain: ChainName,
    pub source_address: Address,
    pub payload_hash: HexBinary,
}

#[cw_serde]
pub struct Address(nonempty::String);

impl Deref for Address {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl FromStr for Address {
    type Err = Report<ContractError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::try_from(s.to_string())
    }
}

impl TryFrom<String> for Address {
    type Error = Report<ContractError>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Address(
            value
                .parse::<nonempty::String>()
                .change_context(ContractError::InvalidAddress)?,
        ))
    }
}

#[cw_serde]
#[serde(try_from = "String")]
#[derive(Eq, Hash)]
pub struct MessageId(String);

impl FromStr for MessageId {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // todo: should split in exactly 2 parts when migrated to state::NewMessage
        let split: Vec<_> = s.split(ID_SEPARATOR).filter(|s| !s.is_empty()).collect();
        if split.len() < 2 {
            return Err(ContractError::InvalidMessageId);
        }
        Ok(MessageId(s.to_lowercase()))
    }
}

impl TryFrom<String> for MessageId {
    type Error = ContractError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().parse()
    }
}

impl From<MessageId> for String {
    fn from(d: MessageId) -> Self {
        d.0
    }
}

impl Deref for MessageId {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for MessageId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> PrimaryKey<'a> for MessageId {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_bytes())]
    }
}

impl KeyDeserialize for MessageId {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self> {
        let value = String::from_utf8(value).map_err(StdError::invalid_utf8)?;
        Ok(Self(value))
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct CrossChainId {
    pub chain: ChainName,
    pub id: MessageId,
}

/// todo: remove this when state::NewMessage is used
impl FromStr for CrossChainId {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split_once(ID_SEPARATOR);
        let (chain, id) = parts
            .map(|(chain, id)| (chain.parse::<ChainName>(), id.parse::<MessageId>()))
            .ok_or(ContractError::InvalidMessageId)?;
        Ok(CrossChainId {
            chain: chain?,
            id: id?,
        })
    }
}

impl Display for CrossChainId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", &self.chain, ID_SEPARATOR, &self.id)
    }
}

impl PrimaryKey<'_> for CrossChainId {
    type Prefix = ChainName;
    type SubPrefix = ();
    type Suffix = MessageId;
    type SuperSuffix = (ChainName, MessageId);

    fn key(&self) -> Vec<Key> {
        let mut keys = self.chain.key();
        keys.extend(self.id.key());
        keys
    }
}

impl KeyDeserialize for CrossChainId {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let (chain, id) = <(ChainName, MessageId)>::from_vec(value)?;
        Ok(CrossChainId { chain, id })
    }
}

#[cw_serde]
#[serde(try_from = "String")]
#[derive(Eq, Hash)]
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

impl PartialEq<String> for ChainName {
    fn eq(&self, other: &String) -> bool {
        self.0 == other.to_lowercase()
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
    use super::*;

    use cosmwasm_std::to_vec;
    use hex;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use sha3::{Digest, Sha3_256};

    use crate::ContractError;

    #[test]
    fn create_correct_global_message_id() {
        let msg = dummy_message();

        assert_eq!(msg.cc_id.to_string(), "chain:hash:index".to_string());
    }

    #[test]
    // Any modifications to the Message struct fields or their types
    // will cause this test to fail, indicating that a migration is needed.
    fn test_message_struct_unchanged() {
        let expected_message_hash =
            "252e44129132a3bac9b26ee4d7f247453bd80b2aa0513050c274d5c5cf2f7153";

        let msg = dummy_message();

        assert_eq!(
            hex::encode(Sha3_256::digest(&to_vec(&msg).unwrap())),
            expected_message_hash
        );
    }

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
    fn chain_name_case_insensitive_comparison() {
        let chain_name = ChainName::from_str("ethereum").unwrap();

        assert!(chain_name.eq(&"Ethereum".to_string()));
        assert!(chain_name.eq(&"ETHEREUM".to_string()));
        assert!(chain_name.eq(&"ethereum".to_string()));
        assert!(chain_name.eq(&"ethEReum".to_string()));

        assert!(!chain_name.eq(&"Ethereum-1".to_string()));
    }

    #[test]
    fn message_id_must_have_at_least_one_separator() {
        assert!(MessageId::from_str("source_chain:hash:id").is_ok());
        assert!(serde_json::from_str::<MessageId>("\"source_chain:hash:id\"").is_ok());

        assert!(MessageId::from_str("invalid_hash").is_err());
        assert!(serde_json::from_str::<MessageId>("\"invalid_hash\"").is_err());

        assert!(MessageId::from_str("invalid_hash:").is_err());
    }

    #[test]
    fn message_id_is_lower_case() {
        let msg_id = "HaSH:iD".parse::<MessageId>().unwrap();
        assert_eq!(msg_id.to_string(), "hash:id");
    }

    #[test]
    fn serialize_global_message_id() {
        let id = CrossChainId {
            chain: "ethereum".parse().unwrap(),
            id: "hash:id".parse().unwrap(),
        };

        let serialized = serde_json::to_string(&id).unwrap();
        assert_eq!(id, serde_json::from_str(&serialized).unwrap());
    }

    fn dummy_message() -> Message {
        Message {
            cc_id: CrossChainId {
                id: "hash:index".parse().unwrap(),
                chain: "chain".parse().unwrap(),
            },
            source_address: "source_address".parse().unwrap(),
            destination_chain: "destination_chain".parse().unwrap(),
            destination_address: "destination_address".parse().unwrap(),
            payload_hash: [1; 32].into(),
        }
    }
}

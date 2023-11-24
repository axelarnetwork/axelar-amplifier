use std::any::type_name;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, Order, StdError, StdResult, Storage};
use cw_storage_plus::{
    Index, IndexList, IndexedMap, Item, Key, KeyDeserialize, MultiIndex, Prefixer, PrimaryKey,
};
use error_stack::{Report, ResultExt};
use flagset::flags;
use mockall::automock;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use axelar_wasm_std::flagset::FlagSet;
use axelar_wasm_std::{nonempty, FnExt};
use sha3::{Digest, Keccak256};

use crate::ContractError;

pub const ID_SEPARATOR: char = ':';

#[automock]
pub trait Store {
    fn save_config(&mut self, config: Config) -> error_stack::Result<(), ContractError>;
    fn load_config(&self) -> error_stack::Result<Config, ContractError>;
    fn load_chain_by_gateway(
        &self,
        gateway: &Addr,
    ) -> error_stack::Result<Option<ChainEndpoint>, ContractError>;
    fn load_chain_by_chain_name(
        &self,
        chain_name: &ChainName,
    ) -> error_stack::Result<Option<ChainEndpoint>, ContractError>;
}

pub struct RouterStore<'a> {
    storage: &'a mut dyn Storage,
}

impl Store for RouterStore<'_> {
    fn save_config(&mut self, config: Config) -> error_stack::Result<(), ContractError> {
        CONFIG
            .save(self.storage, &config)
            .change_context(ContractError::StoreFailure)
    }

    fn load_config(&self) -> error_stack::Result<Config, ContractError> {
        CONFIG
            .load(self.storage)
            .change_context(ContractError::StoreFailure)
    }

    fn load_chain_by_gateway(
        &self,
        gateway: &Addr,
    ) -> error_stack::Result<Option<ChainEndpoint>, ContractError> {
        chain_endpoints()
            .idx
            .gateway
            .load_chain_by_gateway(self.storage, gateway)
            .change_context(ContractError::StoreFailure)
    }

    fn load_chain_by_chain_name(
        &self,
        chain_name: &ChainName,
    ) -> error_stack::Result<Option<ChainEndpoint>, ContractError> {
        chain_endpoints()
            .may_load(self.storage, chain_name.clone())
            .change_context(ContractError::StoreFailure)
    }
}

impl<'a> RouterStore<'a> {
    pub fn new(storage: &'a mut dyn Storage) -> Self {
        Self { storage }
    }
}

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

    #[deprecated(note = "use load_chain_by_gateway instead")]
    pub fn find_chain(
        &self,
        deps: &DepsMut,
        contract_address: &Addr,
    ) -> StdResult<Option<ChainEndpoint>> {
        self.load_chain_by_gateway(deps.storage, contract_address)
    }

    fn load_chain_by_gateway(
        &self,
        storage: &dyn Storage,
        contract_address: &Addr,
    ) -> StdResult<Option<ChainEndpoint>> {
        match self
            .0
            .prefix(contract_address.clone())
            .range(storage, None, None, Order::Ascending)
            .collect::<Result<Vec<_>, _>>()?
            .as_slice()
        {
            [] => Ok(None),
            [(_, chain)] => Ok(Some(chain.to_owned())),
            _ => panic!("More than one gateway for chain"),
        }
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
    pub source_address: Address,
    pub destination_chain: ChainName,
    pub destination_address: Address,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce it's format.
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub payload_hash: [u8; 32],
}

pub type MessageHash = [u8; 32];

impl Message {
    // TODO: pending to finalize the design of the message hash
    pub fn hash_id(&self) -> MessageHash {
        let mut hasher = Keccak256::new();
        hasher.update(self.cc_id.to_string());
        hasher.update(self.source_address.as_str());
        hasher.update(self.destination_chain.as_ref());
        hasher.update(self.destination_address.as_str());
        hasher.update(self.payload_hash);
        hasher.finalize().into()
    }
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
#[derive(Eq, Hash)]
pub struct CrossChainId {
    pub chain: ChainName,
    pub id: nonempty::String,
}

/// todo: remove this when state::NewMessage is used
impl FromStr for CrossChainId {
    type Err = ContractError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = s.split_once(ID_SEPARATOR);
        let (chain, id) = parts
            .map(|(chain, id)| {
                (
                    chain.parse::<ChainName>(),
                    id.parse::<nonempty::String>()
                        .map_err(|_| ContractError::InvalidMessageId),
                )
            })
            .ok_or(ContractError::InvalidMessageId)?;
        Ok(CrossChainId {
            chain: chain?,
            id: id?,
        })
    }
}

impl Display for CrossChainId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}", self.chain, ID_SEPARATOR, *self.id)
    }
}

impl PrimaryKey<'_> for CrossChainId {
    type Prefix = ChainName;
    type SubPrefix = ();
    type Suffix = String;
    type SuperSuffix = (ChainName, String);

    fn key(&self) -> Vec<Key> {
        let mut keys = self.chain.key();
        keys.extend(self.id.key());
        keys
    }
}

impl KeyDeserialize for CrossChainId {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let (chain, id) = <(ChainName, String)>::from_vec(value)?;
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

    use cosmwasm_std::to_vec;
    use hex;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use sha3::{Digest, Sha3_256};

    use crate::ContractError;

    #[test]
    // Any modifications to the Message struct fields or their types
    // will cause this test to fail, indicating that a migration is needed.
    fn test_message_struct_unchanged() {
        let expected_message_hash =
            "9f9b9c55ccf5ce5a82f66385cae9e84e402a272fece5a2e22a199dbefc91d8bf";

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

use core::panic;
use std::ops::Deref;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, HexBinary, Order, StdResult};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex};
use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    msg,
    types::{ChainEndpoint, ChainName, MessageID, ID_SEPARATOR},
    ContractError,
};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
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

const DOMAINS_PKEY: &str = "chains";

pub fn chain_endpoints<'a>() -> IndexedMap<'a, ChainName, ChainEndpoint, ChainEndpointIndexes<'a>> {
    return IndexedMap::new(
        DOMAINS_PKEY,
        ChainEndpointIndexes {
            gateway: GatewayIndex::new(
                |_pk: &[u8], d: &ChainEndpoint| d.gateway.address.clone(),
                DOMAINS_PKEY,
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

// Message represents a message for which the fields have been successfully validated.
// This should never be supplied by the user.
#[cw_serde]
pub struct Message {
    pub id: MessageID, // globally unique
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_chain: ChainName,
    pub source_address: String,
    pub payload_hash: HexBinary,
}

impl Message {
    pub fn new(
        id: MessageID,
        destination_address: String,
        destination_chain: ChainName,
        source_chain: ChainName,
        source_address: String,
        payload_hash: HexBinary,
    ) -> Self {
        Message {
            id,
            destination_address,
            destination_chain,
            source_chain,
            source_address,
            payload_hash,
        }
    }
}

impl TryFrom<msg::Message> for Message {
    type Error = ContractError;
    fn try_from(value: msg::Message) -> Result<Self, Self::Error> {
        if value.destination_address.is_empty() || value.source_address.is_empty() {
            return Err(ContractError::InvalidAddress {});
        }
        if !value
            .id
            .starts_with(&format!("{}{}", value.source_chain, ID_SEPARATOR))
        {
            return Err(ContractError::InvalidMessageID {});
        }
        Ok(Message::new(
            value.id.parse()?,
            value.destination_address,
            value.destination_chain.parse()?,
            value.source_chain.parse()?,
            value.source_address,
            value.payload_hash,
        ))
    }
}

impl From<Message> for msg::Message {
    fn from(value: Message) -> Self {
        msg::Message {
            id: value.id.to_string(),
            destination_address: value.destination_address,
            destination_chain: value.destination_chain.to_string(),
            source_address: value.source_address,
            source_chain: value.source_chain.to_string(),
            payload_hash: value.payload_hash,
        }
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct FlagSet<T>(flagset::FlagSet<T>)
where
    flagset::FlagSet<T>: Serialize,
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize;

impl<T> From<T> for FlagSet<T>
where
    flagset::FlagSet<T>: From<T>,
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize,
{
    fn from(flag: T) -> Self {
        FlagSet(flagset::FlagSet::from(flag))
    }
}

impl<T> From<flagset::FlagSet<T>> for FlagSet<T>
where
    flagset::FlagSet<T>: Serialize,
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize,
{
    fn from(flag_set: flagset::FlagSet<T>) -> Self {
        FlagSet(flag_set)
    }
}

impl<T> Deref for FlagSet<T>
where
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize,
{
    type Target = flagset::FlagSet<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'de, T> Deserialize<'de> for FlagSet<T>
where
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        flagset::FlagSet::<T>::deserialize(deserializer).map(FlagSet::from)
    }
}

impl<T> JsonSchema for FlagSet<T>
where
    T: flagset::Flags + Serialize,
    <T as flagset::Flags>::Type: Serialize,
{
    fn schema_name() -> String {
        "FlagSet".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        gen.root_schema_for::<FlagSet<T>>().schema.into()
    }
}

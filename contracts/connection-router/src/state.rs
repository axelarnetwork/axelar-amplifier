use core::panic;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, HexBinary, Order, StdResult};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, Map, MultiIndex};

use crate::{
    msg,
    types::{Chain, ChainName, MessageID, ID_SEPARATOR},
    ContractError,
};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

pub struct ChainIndexes<'a> {
    pub gateway: GatewayIndex<'a>,
}

pub struct GatewayIndex<'a>(MultiIndex<'a, Addr, Chain, ChainName>);

impl<'a> GatewayIndex<'a> {
    pub fn new(
        idx_fn: fn(&[u8], &Chain) -> Addr,
        pk_namespace: &'a str,
        idx_namespace: &'a str,
    ) -> Self {
        GatewayIndex(MultiIndex::new(idx_fn, pk_namespace, idx_namespace))
    }

    pub fn find_chain(&self, deps: &DepsMut, contract_address: &Addr) -> StdResult<Option<Chain>> {
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

pub fn chains<'a>() -> IndexedMap<'a, ChainName, Chain, ChainIndexes<'a>> {
    return IndexedMap::new(
        DOMAINS_PKEY,
        ChainIndexes {
            gateway: GatewayIndex::new(
                |_pk: &[u8], d: &Chain| d.gateway.address.clone(),
                DOMAINS_PKEY,
                "gateways",
            ),
        },
    );
}

impl<'a> IndexList<Chain> for ChainIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<Chain>> + '_> {
        let v: Vec<&dyn Index<Chain>> = vec![&self.gateway.0];
        Box::new(v.into_iter())
    }
}

// a set of all message uuids
pub const MESSAGES: Map<String, ()> = Map::new("messages");

const MESSAGE_QUEUE_SUFFIX: &str = "-messages";
pub fn get_message_queue_id(destination_chain: &ChainName) -> String {
    format!("{}{}", destination_chain.to_string(), MESSAGE_QUEUE_SUFFIX)
}

// Message represents a message for which the fields have been successfully validated.
// This should never be supplied by the user.
#[cw_serde]
pub struct Message {
    id: MessageID, // unique per source chain
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

    pub fn id(&self) -> String {
        format!(
            "{}{}{}",
            self.source_chain.to_string(),
            ID_SEPARATOR,
            self.id.to_string()
        )
    }
}

impl TryFrom<msg::Message> for Message {
    type Error = ContractError;
    fn try_from(value: msg::Message) -> Result<Self, Self::Error> {
        if value.destination_address.is_empty() || value.source_address.is_empty() {
            return Err(ContractError::InvalidAddress {});
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

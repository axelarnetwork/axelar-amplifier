use core::panic;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, HexBinary, Order, StdResult};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex};

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
        if value.destination_address.is_empty() {
            return Err(ContractError::InvalidAddress(value.destination_address));
        }

        if value.source_address.is_empty() {
            return Err(ContractError::InvalidAddress(value.source_address));
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

#[cfg(test)]
mod tests {
    use cosmwasm_std::to_vec;

    use super::Message;

    #[test]
    // Any modifications to the Message struct fields or their types
    // will cause this test to fail, indicating that a migration is needed.
    fn test_message_struct_unchanged() {
        let expected_message_bytes: Vec<u8> = vec![
            123, 34, 105, 100, 34, 58, 123, 34, 118, 97, 108, 117, 101, 34, 58, 34, 99, 104, 97,
            105, 110, 58, 105, 100, 34, 125, 44, 34, 100, 101, 115, 116, 105, 110, 97, 116, 105,
            111, 110, 95, 97, 100, 100, 114, 101, 115, 115, 34, 58, 34, 100, 101, 115, 116, 105,
            110, 97, 116, 105, 111, 110, 95, 97, 100, 100, 114, 101, 115, 115, 34, 44, 34, 100,
            101, 115, 116, 105, 110, 97, 116, 105, 111, 110, 95, 99, 104, 97, 105, 110, 34, 58,
            123, 34, 118, 97, 108, 117, 101, 34, 58, 34, 100, 101, 115, 116, 105, 110, 97, 116,
            105, 111, 110, 95, 99, 104, 97, 105, 110, 34, 125, 44, 34, 115, 111, 117, 114, 99, 101,
            95, 99, 104, 97, 105, 110, 34, 58, 123, 34, 118, 97, 108, 117, 101, 34, 58, 34, 99,
            104, 97, 105, 110, 34, 125, 44, 34, 115, 111, 117, 114, 99, 101, 95, 97, 100, 100, 114,
            101, 115, 115, 34, 58, 34, 115, 111, 117, 114, 99, 101, 95, 97, 100, 100, 114, 101,
            115, 115, 34, 44, 34, 112, 97, 121, 108, 111, 97, 100, 95, 104, 97, 115, 104, 34, 58,
            34, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48,
            49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48,
            49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 48, 49, 34,
            125,
        ];

        let msg = Message {
            id: "chain:id".to_string().parse().unwrap(),
            source_chain: "chain".to_string().parse().unwrap(),
            source_address: "source_address".to_string(),
            destination_chain: "destination_chain".to_string().parse().unwrap(),
            destination_address: "destination_address".to_string(),
            payload_hash: [1; 32].into(),
        };
        assert_eq!(to_vec(&msg).unwrap(), expected_message_bytes);
    }
}

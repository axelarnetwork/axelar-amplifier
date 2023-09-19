#![allow(deprecated)]

use core::panic;
use std::ops::Deref;
use std::str::FromStr;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, HexBinary, Order, StdResult};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex};
use error_stack::{bail, Report, ResultExt};

use axelar_wasm_std::nonempty;

use crate::types::GlobalMessageId;
use crate::{
    msg,
    types::{ChainEndpoint, ChainName, MessageID, ID_SEPARATOR},
    ContractError,
};

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
pub struct NewMessage {
    pub id_on_chain: MessageID, // unique per chain
    pub destination_address: Address,
    pub destination_chain: ChainName,
    pub source_chain: ChainName,
    pub source_address: Address,
    pub payload_hash: HexBinary,
}

impl NewMessage {
    /// Returns a globally unique message id.
    pub fn global_id(&self) -> GlobalMessageId {
        GlobalMessageId::new(self.source_chain.clone(), self.id_on_chain.clone())
    }
}

/// temporary conversion until [Message] is removed
impl TryFrom<NewMessage> for Message {
    type Error = ContractError;

    fn try_from(msg: NewMessage) -> Result<Self, Self::Error> {
        Ok(Message {
            id: format!("{}", msg.global_id()).parse()?,
            destination_address: msg.destination_address.to_string(),
            destination_chain: msg.destination_chain,
            source_chain: msg.source_chain,
            source_address: msg.source_address.to_string(),
            payload_hash: msg.payload_hash,
        })
    }
}

/// temporary conversion until [Message] is removed
impl TryFrom<Message> for NewMessage {
    type Error = Report<ContractError>;

    fn try_from(msg: Message) -> Result<Self, Self::Error> {
        let (chain, id) = msg
            .id
            .split_once(ID_SEPARATOR)
            .ok_or(ContractError::InvalidMessageID)?;

        if chain.parse::<ChainName>()? != msg.source_chain {
            bail!(ContractError::InvalidMessageID);
        }

        Ok(NewMessage {
            id_on_chain: id.parse()?,
            destination_address: msg.destination_address.parse()?,
            destination_chain: msg.destination_chain,
            source_chain: msg.source_chain,
            source_address: msg.source_address.parse()?,
            payload_hash: msg.payload_hash,
        })
    }
}

// Message represents a message for which the fields have been successfully validated.
// This should never be supplied by the user.
#[cw_serde]
#[deprecated(note = "use NewMessage instead")]
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
            return Err(ContractError::InvalidAddress);
        }

        if value.source_address.is_empty() {
            return Err(ContractError::InvalidAddress);
        }

        if !value
            .id
            .starts_with(&format!("{}{}", value.source_chain, ID_SEPARATOR))
        {
            return Err(ContractError::InvalidMessageID);
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
            destination_chain: value.destination_chain.into(),
            source_address: value.source_address,
            source_chain: value.source_chain.into(),
            payload_hash: value.payload_hash,
        }
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

#[cfg(test)]
mod tests {
    use crate::state::NewMessage;
    use cosmwasm_std::to_vec;
    use hex;
    use sha3::{Digest, Sha3_256};

    #[test]
    fn create_correct_global_message_id() {
        let msg = NewMessage {
            id_on_chain: "hash:id".to_string().parse().unwrap(),
            source_chain: "source_chain".to_string().parse().unwrap(),
            source_address: "source_address".parse().unwrap(),
            destination_chain: "destination_chain".parse().unwrap(),
            destination_address: "destination_address".parse().unwrap(),
            payload_hash: [1; 32].into(),
        };

        assert_eq!(
            msg.global_id().to_string(),
            "source_chain:hash:id".to_string()
        );
    }

    #[test]
    // Any modifications to the Message struct fields or their types
    // will cause this test to fail, indicating that a migration is needed.
    fn test_message_struct_unchanged() {
        let expected_message_hash =
            "5f3a7dd295d833e5846820cd394fed714da1b45a8c372f73ec8ad8ec6aef9a0d";

        let msg = NewMessage {
            id_on_chain: "hash:index".parse().unwrap(),
            source_chain: "chain".parse().unwrap(),
            source_address: "source_address".parse().unwrap(),
            destination_chain: "destination_chain".parse().unwrap(),
            destination_address: "destination_address".parse().unwrap(),
            payload_hash: [1; 32].into(),
        };

        assert_eq!(
            hex::encode(Sha3_256::digest(&to_vec(&msg).unwrap())),
            expected_message_hash
        );
    }
}

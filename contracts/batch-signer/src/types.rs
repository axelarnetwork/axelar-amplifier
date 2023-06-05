use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Uint256, Uint64};
use ethabi::ethereum_types;
use std::{fmt::Display, str::FromStr};

use crate::error::ContractError;

pub type KeccackHash = [u8; 32]; // TODO: move to axelar_wasm_std, probably change to newtype with hex encoding (HexBinary/[u8;32])

pub const ID_SEPARATOR: char = '-';

pub struct Message {
    pub id: String,
    pub source_address: String,
    pub source_chain: String,
    pub destination_address: ethereum_types::Address,
    pub payload_hash: KeccackHash,
    pub source_tx_hash: KeccackHash,
    pub source_event_index: Uint64,
}

impl TryFrom<connection_router::types::Message> for Message {
    type Error = ContractError;

    fn try_from(msg: connection_router::types::Message) -> Result<Self, Self::Error> {
        // TODO: confirm message id format
        // TODO: move all id deconstruction to Message struct impl?
        let id = msg.id();
        let id_parts: Vec<&str> = id.split(ID_SEPARATOR).collect();
        let id_parts: [&str; 2] =
            id_parts
                .try_into()
                .map_err(|_| ContractError::InvalidMessage {
                    context: "message id is not in the format of {tx_hash}-{event_index}".into(),
                })?;

        let source_tx_hash =
            hex::decode(id_parts[0]).map_err(|_| ContractError::InvalidMessage {
                context: "source_tx_hash is not a valid hex string".into(),
            })?;
        let source_tx_hash =
            source_tx_hash
                .try_into()
                .map_err(|_| ContractError::InvalidMessage {
                    context: "source_tx_hash is not a valid keccak256 hash".into(),
                })?;

        let source_event_index =
            Uint64::try_from(id_parts[1]).map_err(|_| ContractError::InvalidMessage {
                context: "source_event_index is not a valid uint256".into(),
            })?;

        Ok(Message {
            id,
            source_address: msg.source_address,
            source_chain: msg.source_domain.into(),
            destination_address: ethereum_types::Address::from_str(&msg.destination_address)
                .map_err(|_| ContractError::InvalidMessage {
                    context: "destination_address is not a valid EVM address".into(),
                })?,
            payload_hash: msg.payload_hash.as_slice().try_into().map_err(|_| {
                ContractError::InvalidMessage {
                    context: "payload_hash is not a valid keccak256 hash".into(),
                }
            })?,
            source_tx_hash,
            source_event_index,
        })
    }
}

// TODO: this would most likely change when other command types are supported
impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "approveContractCall")
    }
}

#[cw_serde]
pub struct Proof {
    pub addresses: Vec<Addr>,
    pub weights: Vec<Uint256>,
    pub threshold: Uint256,
    pub signatures: Vec<HexBinary>,
}

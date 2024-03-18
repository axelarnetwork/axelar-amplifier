use axelar_wasm_std::nonempty;
use connection_router_api::{Address, ChainName, CrossChainId};
use cosmwasm_std::{CosmosMsg, CustomMsg};
use error_stack::{Result, ResultExt};
use hex::{FromHex, ToHex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractError;
use voting_verifier::events::TX_HASH_EVENT_INDEX_SEPARATOR;

const ZEROX_PREFIX: &str = "0x";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// this matches the message type defined in the nexus module
// https://github.com/axelarnetwork/axelar-core/blob/6c887df3797ba660093061662aff04e325b9c429/x/nexus/exported/types.pb.go#L405
pub struct Message {
    pub source_chain: ChainName,
    pub source_address: Address,
    pub destination_chain: ChainName,
    pub destination_address: Address,
    pub payload_hash: [u8; 32],
    pub source_tx_id: nonempty::Vec<u8>,
    pub source_tx_index: u64,
}

impl CustomMsg for Message {}

// it's parsed into u64 instead of u32 (https://github.com/axelarnetwork/axelar-amplifier/blob/bf0b3049c83e540989c7dad1c609c7e2ef6ed2e5/contracts/voting-verifier/src/events.rs#L162)
// here in order to match the message type defined in the nexus module. Changing nexus to use u32 instead is not worth the effort.
fn parse_message_id(message_id: &str) -> Result<(nonempty::Vec<u8>, u64), ContractError> {
    // expected format: <tx_id>:<index>
    let components = message_id
        .split(TX_HASH_EVENT_INDEX_SEPARATOR)
        .collect::<Vec<_>>();

    if components.len() != 2 {
        return Err(ContractError::InvalidMessageId(message_id.to_string()).into());
    }

    // TODO: decode differently depending on the chain?
    let tx_id = <Vec<u8>>::from_hex(components[0].trim_start_matches(ZEROX_PREFIX))
        .change_context_lazy(|| ContractError::InvalidMessageId(message_id.to_string()))?;
    let tx_id: nonempty::Vec<u8> = <nonempty::Vec<u8>>::try_from(tx_id)
        .change_context_lazy(|| ContractError::InvalidMessageId(message_id.to_string()))?;
    let index = components[1]
        .parse::<u64>()
        .change_context_lazy(|| ContractError::InvalidMessageId(message_id.to_string()))?;

    Ok((tx_id, index))
}

impl From<connection_router_api::Message> for Message {
    fn from(msg: connection_router_api::Message) -> Self {
        // fallback to using the message ID as the tx ID if it's not in the expected format
        let (source_tx_id, source_tx_index) =
            parse_message_id(&msg.cc_id.id).unwrap_or((msg.cc_id.id.into(), u64::MAX));

        Self {
            source_chain: msg.cc_id.chain,
            source_address: msg.source_address,
            destination_chain: msg.destination_chain,
            destination_address: msg.destination_address,
            payload_hash: msg.payload_hash,
            source_tx_id,
            source_tx_index,
        }
    }
}

impl From<Message> for connection_router_api::Message {
    fn from(msg: Message) -> Self {
        Self {
            cc_id: CrossChainId {
                chain: msg.source_chain,
                id: format!(
                    "{}:{}",
                    msg.source_tx_id.as_ref().encode_hex::<String>(),
                    msg.source_tx_index
                )
                .try_into()
                .expect("cannot be empty"),
            },
            source_address: msg.source_address,
            destination_chain: msg.destination_chain,
            destination_address: msg.destination_address,
            payload_hash: msg.payload_hash,
        }
    }
}

impl From<Message> for CosmosMsg<Message> {
    fn from(msg: Message) -> Self {
        CosmosMsg::Custom(msg)
    }
}

use axelar_wasm_std::nonempty;
use connection_router::state::{Address, ChainName, Message as RouterMessage, ID_SEPARATOR};
use cosmwasm_std::{CosmosMsg, CustomMsg};
use error_stack::{Report, Result, ResultExt};
use hex::FromHex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractError;

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

fn parse_message_id(message_id: &str) -> Result<(nonempty::Vec<u8>, u64), ContractError> {
    // expected format: <tx_id>:<index>
    let components = message_id.split(ID_SEPARATOR).collect::<Vec<_>>();

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

impl TryFrom<RouterMessage> for Message {
    type Error = Report<ContractError>;

    fn try_from(msg: RouterMessage) -> Result<Self, ContractError> {
        // fallback to using the message ID as the tx ID if it's not in the expected format
        let (source_tx_id, source_tx_index) =
            parse_message_id(&msg.cc_id.id).unwrap_or((msg.cc_id.id.into(), u64::MAX));
        let payload_hash: [u8; 32] = msg
            .payload_hash
            .to_array()
            .change_context(ContractError::InvalidMessagePayloadHash(msg.payload_hash))?;

        Ok(Self {
            source_chain: msg.cc_id.chain,
            source_address: msg.source_address.clone(),
            destination_chain: msg.destination_chain,
            destination_address: msg.destination_address.clone(),
            payload_hash,
            source_tx_id,
            source_tx_index,
        })
    }
}

impl From<Message> for CosmosMsg<Message> {
    fn from(msg: Message) -> Self {
        CosmosMsg::Custom(msg)
    }
}

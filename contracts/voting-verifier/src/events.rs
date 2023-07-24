use std::fmt;

use axelar_wasm_std::voting::PollID;
use connection_router::state::Message;
use connection_router::types::ID_SEPARATOR;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Event, HexBinary};

use crate::error::ContractError;
use crate::state::Config;

impl From<Config> for Event {
    fn from(other: Config) -> Self {
        Event::new("instantiated")
            .add_attribute("service_name", other.service_name)
            .add_attribute("service_registry_contract", other.service_registry)
            .add_attribute("source_gateway_address", other.source_gateway_address)
            .add_attribute("voting_threshold", other.voting_threshold.to_string())
            .add_attribute("block_expiry", other.block_expiry.to_string())
            .add_attribute("confirmation_height", other.confirmation_height.to_string())
    }
}

pub struct PollStarted {
    pub poll_id: PollID,
    pub source_gateway_address: String,
    pub confirmation_height: u64,
    pub messages: Vec<Message>,
    pub participants: Vec<Addr>,
}

impl TryFrom<PollStarted> for Event {
    type Error = ContractError;

    fn try_from(other: PollStarted) -> Result<Self, Self::Error> {
        let source_chain = other.messages[0].source_chain.to_string();

        let evm_messages = other
            .messages
            .into_iter()
            .map(EvmMessage::try_from)
            .collect::<Result<Vec<_>, ContractError>>()?;

        Ok(Event::new("poll_started")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute("source_chain", source_chain)
            .add_attribute("source_gateway_address", other.source_gateway_address)
            .add_attribute("confirmation_height", other.confirmation_height.to_string())
            .add_attribute("participants", display_vector(other.participants))
            .add_attribute("messages", display_vector(evm_messages)))
    }
}

#[cw_serde]
pub struct EvmMessage {
    pub tx_id: String,
    pub index: u64,
    pub destination_address: String,
    pub destination_chain: String,
    pub source_address: String,
    pub payload_hash: HexBinary,
}

impl TryFrom<Message> for EvmMessage {
    type Error = ContractError;

    fn try_from(other: Message) -> Result<Self, Self::Error> {
        let (tx_id, index) = parse_message_id(other.id.to_string())?;

        Ok(EvmMessage {
            tx_id,
            index,
            destination_address: other.destination_address,
            destination_chain: other.destination_chain.to_string(),
            source_address: other.source_address,
            payload_hash: other.payload_hash,
        })
    }
}

fn parse_message_id(message_id: String) -> Result<(String, u64), ContractError> {
    // expected format: <source_chain>:<tx_id>:<index>
    let components = message_id.split(ID_SEPARATOR).collect::<Vec<_>>();

    if components.len() != 3 {
        return Err(ContractError::InvalidMessageID(message_id));
    }

    Ok((
        components[1].to_string(),
        components[2]
            .parse::<u64>()
            .map_err(|_| ContractError::InvalidMessageID(message_id))?,
    ))
}

impl fmt::Display for EvmMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let serialized = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        write!(f, "{}", serialized)
    }
}

fn display_vector<T>(v: Vec<T>) -> String
where
    T: std::fmt::Display,
{
    format!(
        "[{}]",
        v.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

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
    pub source_chain: String,
    pub source_gateway_address: String,
    pub confirmation_height: u64,
    pub expires_at: u64,
    pub messages: Vec<EvmMessage>,
    pub participants: Vec<Addr>,
}

impl PollStarted {
    pub fn new(
        poll_id: PollID,
        source_gateway_address: String,
        confirmation_height: u64,
        expires_at: u64,
        messages: Vec<Message>,
        participants: Vec<Addr>,
    ) -> Result<PollStarted, ContractError> {
        let source_chain = messages[0].source_chain.to_string();

        let messages = messages
            .into_iter()
            .map(EvmMessage::try_from)
            .collect::<Result<Vec<_>, ContractError>>()?;

        Ok(PollStarted {
            poll_id,
            source_chain,
            source_gateway_address,
            confirmation_height,
            expires_at,
            messages,
            participants,
        })
    }
}

impl From<PollStarted> for Event {
    fn from(other: PollStarted) -> Self {
        Event::new("poll_started")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute("source_chain", other.source_chain)
            .add_attribute("source_gateway_address", other.source_gateway_address)
            .add_attribute("confirmation_height", other.confirmation_height.to_string())
            .add_attribute("expires_at", other.expires_at.to_string())
            .add_attribute("participants", display_vector(other.participants))
            .add_attribute("messages", display_vector(other.messages))
    }
}

#[cw_serde]
pub struct EvmMessage {
    tx_id: String,
    log_index: u64,
    destination_address: String,
    destination_chain: String,
    source_address: String,
    payload_hash: HexBinary,
}

impl TryFrom<Message> for EvmMessage {
    type Error = ContractError;

    fn try_from(other: Message) -> Result<Self, Self::Error> {
        let (tx_id, log_index) = parse_message_id(other.id.to_string())?;

        Ok(EvmMessage {
            tx_id,
            log_index,
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
    T: fmt::Display,
{
    format!(
        "[{}]",
        v.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

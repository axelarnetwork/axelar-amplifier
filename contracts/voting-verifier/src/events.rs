use std::str::FromStr;
use std::vec::Vec;

use axelar_wasm_std::operators::Operators;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Event, HexBinary};

use axelar_wasm_std::voting::PollID;
use connection_router::state::Message;
use connection_router::types::{ChainName, MessageID, ID_SEPARATOR};

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
    pub source_chain: ChainName,
    pub source_gateway_address: String,
    pub confirmation_height: u64,
    pub expires_at: u64,
    pub data: PollData,
    pub participants: Vec<Addr>,
}

pub enum PollData {
    Messages(Vec<EvmMessage>),
    WorkerSet(WorkerSetConfirmation),
}

fn get_data_attribute(data: PollData) -> (String, String) {
    match data {
        PollData::Messages(msgs) => (
            "messages".into(),
            serde_json::to_string(&msgs).expect("failed to serialize messages"),
        ),
        PollData::WorkerSet(worker_set_confirmation) => (
            "worker_set_confirmation".into(),
            serde_json::to_string(&worker_set_confirmation)
                .expect("failed to serialize worker set confirmation"),
        ),
    }
}

impl From<PollStarted> for Event {
    fn from(other: PollStarted) -> Self {
        let (data_attr_name, data_val) = get_data_attribute(other.data);
        Event::new("poll_started")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute("source_chain", other.source_chain)
            .add_attribute("source_gateway_address", other.source_gateway_address)
            .add_attribute("confirmation_height", other.confirmation_height.to_string())
            .add_attribute("expires_at", other.expires_at.to_string())
            .add_attribute(
                "participants",
                serde_json::to_string(&other.participants)
                    .expect("failed to serialize participants"),
            )
            .add_attribute(data_attr_name, data_val)
    }
}

pub struct EvmMessages(pub ChainName, pub Vec<EvmMessage>);

impl TryFrom<Vec<Message>> for EvmMessages {
    type Error = ContractError;

    fn try_from(other: Vec<Message>) -> Result<Self, Self::Error> {
        let source_chain = other[0].source_chain.clone();

        if other
            .iter()
            .any(|message| !message.source_chain.eq(&source_chain))
        {
            return Err(ContractError::SourceChainMismatch(source_chain));
        }

        let messages = other
            .into_iter()
            .map(EvmMessage::try_from)
            .collect::<Result<Vec<_>, ContractError>>()?;

        Ok(EvmMessages(source_chain, messages))
    }
}

#[cw_serde]
pub struct WorkerSetConfirmation {
    pub tx_id: String,
    pub log_index: u64,
    pub operators: Operators,
}

impl WorkerSetConfirmation {
    pub fn new(message_id: MessageID, operators: Operators) -> Result<Self, ContractError> {
        let (tx_id, log_index) = parse_message_id(message_id.to_string())?;
        Ok(Self {
            tx_id,
            log_index,
            operators,
        })
    }
}

#[cw_serde]
pub struct EvmMessage {
    pub tx_id: String,
    pub log_index: u64,
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_address: String,
    pub payload_hash: HexBinary,
}

impl TryFrom<Message> for EvmMessage {
    type Error = ContractError;

    fn try_from(other: Message) -> Result<Self, Self::Error> {
        let (tx_id, log_index) = parse_message_id(other.id.to_string())?;

        Ok(EvmMessage {
            tx_id,
            log_index,
            destination_address: other.destination_address,
            destination_chain: other.destination_chain,
            source_address: other.source_address,
            payload_hash: other.payload_hash,
        })
    }
}

impl FromStr for EvmMessage {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
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

pub struct Voted {
    pub poll_id: PollID,
    pub voter: Addr,
}

impl From<Voted> for Event {
    fn from(other: Voted) -> Self {
        Event::new("voted")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute("voter", other.voter)
    }
}

pub struct PollEnded {
    pub poll_id: PollID,
    pub results: Vec<bool>,
}

impl From<PollEnded> for Event {
    fn from(other: PollEnded) -> Self {
        Event::new("poll_ended")
            .add_attribute("poll_id", other.poll_id)
            .add_attribute(
                "results",
                serde_json::to_string(&other.results).expect("failed to serialize results"),
            )
    }
}

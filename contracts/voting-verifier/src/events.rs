use std::str::FromStr;
use std::vec::Vec;

use axelar_wasm_std::operators::Operators;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Attribute, Event, HexBinary};
use serde_json::to_string;

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

pub struct PollMetadata {
    pub poll_id: PollID,
    pub source_chain: ChainName,
    pub source_gateway_address: String,
    pub confirmation_height: u64,
    pub expires_at: u64,
    pub participants: Vec<Addr>,
}

pub enum PollStarted {
    Messages {
        messages: Vec<EvmMessage>,
        metadata: PollMetadata,
    },
    WorkerSet {
        worker_set: WorkerSetConfirmation,
        metadata: PollMetadata,
    },
}

impl From<PollMetadata> for Vec<Attribute> {
    fn from(value: PollMetadata) -> Self {
        vec![
            (
                "poll_id",
                to_string(&value.poll_id).expect("failed to serialize poll_id"),
            ),
            (
                "source_chain",
                to_string(&value.source_chain).expect("failed to serialize source_chain"),
            ),
            ("source_gateway_address", value.source_gateway_address),
            ("confirmation_height", value.confirmation_height.to_string()),
            ("expires_at", value.expires_at.to_string()),
            (
                "participants",
                to_string(&value.participants).expect("failed to serialize participants"),
            ),
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }
}

impl From<PollStarted> for Event {
    fn from(other: PollStarted) -> Self {
        match other {
            PollStarted::Messages {
                messages: data,
                metadata,
            } => Event::new("messages_poll_started")
                .add_attribute(
                    "messages",
                    to_string(&data).expect("failed to serialize messages"),
                )
                .add_attributes(Vec::<_>::from(metadata)),
            PollStarted::WorkerSet {
                worker_set: data,
                metadata,
            } => Event::new("worker_set_poll_started")
                .add_attribute(
                    "worker_set",
                    to_string(&data).expect("failed to serialize worker set confirmation"),
                )
                .add_attributes(Vec::<_>::from(metadata)),
        }
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
        let (tx_id, log_index) = parse_message_id(&message_id)?;
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
        let (tx_id, log_index) = parse_message_id(&other.id)?;

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

fn parse_message_id(message_id: &MessageID) -> Result<(String, u64), ContractError> {
    // expected format: <source_chain>:<tx_id>:<index>
    let components = message_id.as_str().split(ID_SEPARATOR).collect::<Vec<_>>();

    if components.len() != 3 {
        return Err(ContractError::InvalidMessageID(message_id.clone()));
    }

    Ok((
        components[1].to_string(),
        components[2]
            .parse::<u64>()
            .map_err(|_| ContractError::InvalidMessageID(message_id.clone()))?,
    ))
}

pub struct Voted {
    pub poll_id: PollID,
    pub voter: Addr,
}

impl From<Voted> for Event {
    fn from(other: Voted) -> Self {
        Event::new("voted")
            .add_attribute(
                "poll_id",
                to_string(&other.poll_id).expect("failed to serialize poll_id"),
            )
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
            .add_attribute(
                "poll_id",
                to_string(&other.poll_id).expect("failed to serialize poll_id"),
            )
            .add_attribute(
                "results",
                to_string(&other.results).expect("failed to serialize results"),
            )
    }
}

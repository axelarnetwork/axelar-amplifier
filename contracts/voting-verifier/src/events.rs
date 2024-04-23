use std::vec::Vec;

use axelar_wasm_std::hash::Hash;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Attribute, Event, HexBinary};

use axelar_wasm_std::nonempty;
use axelar_wasm_std::operators::Operators;
use axelar_wasm_std::voting::{PollId, Vote};
use router_api::{Address, ChainName, Message};

pub const TX_HASH_EVENT_INDEX_SEPARATOR: char = '-';

use crate::error::ContractError;
use crate::state::Config;

impl From<Config> for Vec<Attribute> {
    fn from(other: Config) -> Self {
        vec![
            ("service_name", other.service_name.to_string()),
            (
                "service_registry_contract",
                other.service_registry_contract.to_string(),
            ),
            (
                "source_gateway_address",
                other.source_gateway_address.to_string(),
            ),
            (
                "voting_threshold",
                serde_json::to_string(&other.voting_threshold)
                    .expect("failed to serialize voting_threshold"),
            ),
            ("block_expiry", other.block_expiry.to_string()),
            ("confirmation_height", other.confirmation_height.to_string()),
        ]
        .into_iter()
        .map(Attribute::from)
        .collect()
    }
}

pub struct PollMetadata {
    pub poll_id: PollId,
    pub source_chain: ChainName,
    pub source_gateway_address: nonempty::String,
    pub confirmation_height: u64,
    pub expires_at: u64,
    pub participants: Vec<Addr>,
}

pub enum PollStarted {
    Messages {
        messages: Vec<TxEventConfirmation>,
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
                &serde_json::to_string(&value.poll_id).expect("failed to serialize poll_id"),
            ),
            ("source_chain", &value.source_chain.to_string()),
            ("source_gateway_address", &value.source_gateway_address),
            (
                "confirmation_height",
                &value.confirmation_height.to_string(),
            ),
            ("expires_at", &value.expires_at.to_string()),
            (
                "participants",
                &serde_json::to_string(&value.participants)
                    .expect("failed to serialize participants"),
            ),
        ]
        .into_iter()
        .map(Attribute::from)
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
                    serde_json::to_string(&data).expect("failed to serialize messages"),
                )
                .add_attributes(Vec::<_>::from(metadata)),
            PollStarted::WorkerSet {
                worker_set: data,
                metadata,
            } => Event::new("worker_set_poll_started")
                .add_attribute(
                    "worker_set",
                    serde_json::to_string(&data)
                        .expect("failed to serialize worker set confirmation"),
                )
                .add_attributes(Vec::<_>::from(metadata)),
        }
    }
}

#[cw_serde]
pub struct WorkerSetConfirmation {
    pub tx_id: nonempty::String,
    pub event_index: u32,
    pub operators: Operators,
}

impl WorkerSetConfirmation {
    pub fn new(message_id: nonempty::String, operators: Operators) -> Result<Self, ContractError> {
        let (tx_id, event_index) = parse_message_id(&message_id)?;

        Ok(Self {
            tx_id,
            event_index,
            operators,
        })
    }
}

#[cw_serde]
pub struct TxEventConfirmation {
    pub tx_id: nonempty::String,
    pub event_index: u32,
    pub destination_address: Address,
    pub destination_chain: ChainName,
    pub source_address: Address,
    /// for better user experience, the payload hash gets encoded into hex at the edges (input/output),
    /// but internally, we treat it as raw bytes to enforce its format.
    #[serde(with = "axelar_wasm_std::hex")]
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub payload_hash: [u8; 32],
}

impl TryFrom<Message> for TxEventConfirmation {
    type Error = ContractError;

    fn try_from(other: Message) -> Result<Self, Self::Error> {
        let (tx_id, event_index) = parse_message_id(&other.cc_id.id)?;

        Ok(TxEventConfirmation {
            tx_id,
            event_index,
            destination_address: other.destination_address,
            destination_chain: other.destination_chain,
            source_address: other.source_address,
            payload_hash: other.payload_hash,
        })
    }
}

fn parse_message_id(
    message_id: &nonempty::String,
) -> Result<(nonempty::String, u32), ContractError> {
    // expected format: <tx_id>:<index>
    let components = message_id
        .split(TX_HASH_EVENT_INDEX_SEPARATOR)
        .collect::<Vec<_>>();

    if components.len() != 2 {
        return Err(ContractError::InvalidMessageID(message_id.to_string()));
    }

    let event_index = components[1];
    if event_index != "0" && event_index.starts_with('0') {
        return Err(ContractError::InvalidMessageID(message_id.to_string()));
    }

    Ok((
        components[0].try_into()?,
        event_index
            .parse()
            .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?,
    ))
}

pub fn construct_message_id(tx_hash: Hash, event_index: u32) -> String {
    format!(
        "{}{}{}",
        HexBinary::from(tx_hash),
        TX_HASH_EVENT_INDEX_SEPARATOR,
        event_index
    )
}

pub struct Voted {
    pub poll_id: PollId,
    pub voter: Addr,
}

impl From<Voted> for Event {
    fn from(other: Voted) -> Self {
        Event::new("voted")
            .add_attribute(
                "poll_id",
                serde_json::to_string(&other.poll_id).expect("failed to serialize poll_id"),
            )
            .add_attribute("voter", other.voter)
    }
}

pub struct PollEnded {
    pub poll_id: PollId,
    pub results: Vec<Option<Vote>>,
}

impl From<PollEnded> for Event {
    fn from(other: PollEnded) -> Self {
        Event::new("poll_ended")
            .add_attribute(
                "poll_id",
                serde_json::to_string(&other.poll_id).expect("failed to serialize poll_id"),
            )
            .add_attribute(
                "results",
                serde_json::to_string(&other.results).expect("failed to serialize results"),
            )
    }
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::HexBinary;

    use crate::events::{construct_message_id, parse_message_id, TX_HASH_EVENT_INDEX_SEPARATOR};

    #[test]
    fn should_be_able_to_parse_and_then_reconstruct_msg_id() {
        let message_id: nonempty::String = format!(
            "{}{}{}",
            "a83c04cc4b86ae3095f2d0db4180db2c4065f1506955b244eda65d3a1ce733af",
            TX_HASH_EVENT_INDEX_SEPARATOR,
            1
        )
        .try_into()
        .unwrap();
        let (hash, event_index) = parse_message_id(&message_id).unwrap();
        let reconstructed = construct_message_id(
            HexBinary::from_hex(&hash)
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
            event_index,
        );
        assert_eq!(message_id.to_string(), reconstructed);
    }

    #[test]
    fn should_not_parse_msg_id_without_event_index() {
        let message_id: nonempty::String =
            "a83c04cc4b86ae3095f2d0db4180db2c4065f1506955b244eda65d3a1ce733af"
                .try_into()
                .unwrap();
        let res = parse_message_id(&message_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_wrong_seperator() {
        let message_id: nonempty::String = format!(
            "{}{}{}",
            "a83c04cc4b86ae3095f2d0db4180db2c4065f1506955b244eda65d3a1ce733af", "+", 1
        )
        .try_into()
        .unwrap();
        let res = parse_message_id(&message_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_msg_id_with_non_integer_event_index() {
        let message_id: nonempty::String =
            "a83c04cc4b86ae3095f2d0db4180db2c4065f1506955b244eda65d3a1ce733af-foobar"
                .try_into()
                .unwrap();
        let res = parse_message_id(&message_id);
        assert!(res.is_err());
    }

    #[test]
    fn should_not_parse_event_index_with_leading_zeroes() {
        let message_id: nonempty::String =
            "a83c04cc4b86ae3095f2d0db4180db2c4065f1506955b244eda65d3a1ce733af-01"
                .try_into()
                .unwrap();
        let res = parse_message_id(&message_id);
        assert!(res.is_err());
    }
}

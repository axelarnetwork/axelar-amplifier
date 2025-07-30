use std::str::FromStr;
use std::vec::Vec;

use axelar_wasm_std::msg_id::{
    Base58SolanaTxSignatureAndEventIndex, Base58TxDigestAndEventIndex, Bech32mFormat,
    FieldElementAndEventIndex, HexTxHash, HexTxHashAndEventIndex, MessageIdFormat,
};
use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{nonempty, VerificationStatus};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Attribute, Event};
use router_api::{Address, ChainName};

use crate::error::ContractError;
use crate::state::Config;

impl From<Config> for Vec<Attribute> {
    fn from(other: Config) -> Self {
        // destructuring the Config struct so changes to the fields don't go unnoticed
        let Config {
            service_name,
            service_registry_contract,
            source_gateway_address,
            voting_threshold,
            block_expiry,
            confirmation_height,
            source_chain,
            rewards_contract,
            msg_id_format,
            address_format,
        } = other;

        vec![
            ("service_name", service_name.to_string()),
            (
                "service_registry_contract",
                service_registry_contract.to_string(),
            ),
            ("source_gateway_address", source_gateway_address.to_string()),
            (
                "voting_threshold",
                serde_json::to_string(&voting_threshold)
                    .expect("failed to serialize voting_threshold"),
            ),
            ("block_expiry", block_expiry.to_string()),
            ("confirmation_height", confirmation_height.to_string()),
            ("source_chain", source_chain.to_string()),
            ("rewards_contract", rewards_contract.to_string()),
            (
                "msg_id_format",
                serde_json::to_string(&msg_id_format).expect("failed to serialize msg_id_format"),
            ),
            (
                "address_format",
                serde_json::to_string(&address_format).expect("failed to serialize address_format"),
            ),
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
    Events {
        events: Vec<TxEventConfirmation>,
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
            PollStarted::Events {
                events: data,
                metadata,
            } => Event::new("events_poll_started")
                .add_attribute(
                    "events",
                    serde_json::to_string(&data).expect("failed to serialize events"),
                )
                .add_attributes(Vec::<_>::from(metadata)),
        }
    }
}

/// If parsing is successful, returns (tx_id, event_index). Otherwise returns ContractError::InvalidMessageID
#[deprecated(since = "1.1.0", note = "don't parse message id, just emit as is")]
fn parse_message_id(
    message_id: &str,
    msg_id_format: &MessageIdFormat,
) -> Result<(nonempty::String, u32), ContractError> {
    match msg_id_format {
        MessageIdFormat::Base58TxDigestAndEventIndex => {
            let id = Base58TxDigestAndEventIndex::from_str(message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?;
            Ok((
                id.tx_digest_as_base58(),
                u32::try_from(id.event_index)
                    .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?,
            ))
        }
        MessageIdFormat::FieldElementAndEventIndex => {
            let id = FieldElementAndEventIndex::from_str(message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?;

            Ok((
                id.tx_hash_as_hex(),
                u32::try_from(id.event_index)
                    .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?,
            ))
        }
        MessageIdFormat::HexTxHashAndEventIndex => {
            let id = HexTxHashAndEventIndex::from_str(message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?;

            Ok((
                id.tx_hash_as_hex(),
                u32::try_from(id.event_index)
                    .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?,
            ))
        }
        MessageIdFormat::Base58SolanaTxSignatureAndEventIndex => {
            let id = Base58SolanaTxSignatureAndEventIndex::from_str(message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?;

            Ok((
                id.signature_as_base58(),
                u32::try_from(id.event_index)
                    .map_err(|_| ContractError::InvalidMessageID(message_id.to_string()))?,
            ))
        }
        MessageIdFormat::HexTxHash => {
            let id = HexTxHash::from_str(message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.into()))?;

            Ok((id.tx_hash_as_hex(), 0))
        }
        MessageIdFormat::Bech32m { prefix, length } => {
            let bech32m_message_id = Bech32mFormat::from_str(prefix, *length as usize, message_id)
                .map_err(|_| ContractError::InvalidMessageID(message_id.into()))?;
            Ok((bech32m_message_id.to_string().try_into()?, 0))
        }
    }
}

#[cw_serde]
pub struct TxEventConfirmation {
    #[deprecated(since = "1.1.0", note = "use message_id field instead")]
    pub tx_id: nonempty::String,
    #[deprecated(since = "1.1.0", note = "use message_id field instead")]
    pub event_index: u32,
    pub message_id: nonempty::String,
    pub source_chain: ChainName,
    pub contract_address: Address,
    /// The actual event data to verify
    pub event_data: crate::msg::EventData,
}

// Message TryFrom implementation removed - message functionality has been removed

impl TryFrom<(crate::msg::EventToVerify, &MessageIdFormat)> for TxEventConfirmation {
    type Error = ContractError;
    fn try_from(
        (event, msg_id_format): (crate::msg::EventToVerify, &MessageIdFormat),
    ) -> Result<Self, Self::Error> {
        #[allow(deprecated)]
        let (tx_id, event_index) = parse_message_id(&event.event_id.message_id, msg_id_format)?;

        #[allow(deprecated)]
        // TODO: remove this attribute when tx_id and event_index are removed from the event
        Ok(TxEventConfirmation {
            tx_id,
            event_index,
            message_id: event.event_id.message_id.try_into().unwrap(),
            source_chain: event.event_id.source_chain,
            contract_address: event.event_id.contract_address,
            event_data: event.event_data,
        })
    }
}

pub struct Voted {
    pub poll_id: PollId,
    pub voter: Addr,
    pub votes: Vec<Vote>,
}

impl From<Voted> for Event {
    fn from(other: Voted) -> Self {
        Event::new("voted")
            .add_attribute(
                "poll_id",
                serde_json::to_string(&other.poll_id).expect("failed to serialize poll_id"),
            )
            .add_attribute("voter", other.voter)
            .add_attribute(
                "votes",
                serde_json::to_string(&other.votes).expect("failed to serialize votes"),
            )
    }
}

pub struct PollEnded {
    pub poll_id: PollId,
    pub source_chain: ChainName,
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
                "source_chain",
                serde_json::to_string(&other.source_chain)
                    .expect("failed to serialize source_chain"),
            )
            .add_attribute(
                "results",
                serde_json::to_string(&other.results).expect("failed to serialize results"),
            )
    }
}

pub struct QuorumReached<T> {
    pub content: T,
    pub status: VerificationStatus,
    pub poll_id: PollId,
}

impl<T> From<QuorumReached<T>> for Event
where
    T: cosmwasm_schema::serde::Serialize,
{
    fn from(value: QuorumReached<T>) -> Self {
        Event::new("quorum_reached")
            .add_attribute(
                "content",
                serde_json::to_string(&value.content).expect("failed to serialize content"),
            )
            .add_attribute(
                "status",
                serde_json::to_string(&value.status).expect("failed to serialize status"),
            )
            .add_attribute(
                "poll_id",
                serde_json::to_string(&value.poll_id).expect("failed to serialize poll_id"),
            )
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::msg_id::{
        Base58TxDigestAndEventIndex, HexTxHash, HexTxHashAndEventIndex, MessageIdFormat,
    };
    use cosmwasm_std::testing::MockApi;
    use cosmwasm_std::{Api, Event as CosmosEvent};

    use super::*;

    // All message-related tests removed since message functionality has been removed from event-verifier

    #[test]
    fn should_serialize_events_poll_started() {
        let api = MockApi::default();

        let event_events_poll_started: cosmwasm_std::Event = PollStarted::Events {
            events: vec![
                TxEventConfirmation {
                    tx_id: "txId1".try_into().unwrap(),
                    event_index: 1,
                    message_id: "messageId".try_into().unwrap(),
                    source_chain: "sourceChain".try_into().unwrap(),
                    contract_address: "contractAddress1".parse().unwrap(),
                    event_data: crate::msg::EventData::Evm {
                        topics: vec![cosmwasm_std::HexBinary::from(vec![1, 2, 3])],
                        data: cosmwasm_std::HexBinary::from(vec![1, 2, 3, 4]),
                    },
                },
                TxEventConfirmation {
                    tx_id: "txId2".try_into().unwrap(),
                    event_index: 2,
                    message_id: "messageId".try_into().unwrap(),
                    source_chain: "sourceChain".try_into().unwrap(),
                    contract_address: "contractAddress2".parse().unwrap(),
                    event_data: crate::msg::EventData::Evm {
                        topics: vec![cosmwasm_std::HexBinary::from(vec![1, 2, 3])],
                        data: cosmwasm_std::HexBinary::from(vec![5, 6, 7, 8]),
                    },
                },
            ],
            metadata: PollMetadata {
                poll_id: 1.into(),
                source_chain: "sourceChain".try_into().unwrap(),
                source_gateway_address: "sourceGatewayAddress".try_into().unwrap(),
                confirmation_height: 1,
                expires_at: 1,
                participants: vec![
                    api.addr_make("participant1"),
                    api.addr_make("participant2"),
                    api.addr_make("participant3"),
                ],
            },
        }
        .into();

        goldie::assert_json!(event_events_poll_started);
    }
}

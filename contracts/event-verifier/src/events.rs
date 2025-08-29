use std::vec::Vec;

use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{nonempty, VerificationStatus};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Attribute, Event};
use router_api::ChainName;

use crate::error::ContractError;
use crate::state::Config;

impl From<Config> for Vec<Attribute> {
    fn from(other: Config) -> Self {
        // destructuring the Config struct so changes to the fields don't go unnoticed
        let Config {
            service_name,
            service_registry_contract,
            admin,
            voting_threshold,
            block_expiry,
            fee,
        } = other;

        vec![
            ("service_name", service_name.to_string()),
            (
                "service_registry_contract",
                service_registry_contract.to_string(),
            ),
            ("admin", admin.to_string()),
            ("voting_threshold", serde_json::to_string(&voting_threshold)
                .expect("failed to serialize voting_threshold")),
            ("block_expiry", block_expiry.to_string()),
            ("fee", serde_json::to_string(&fee).expect("failed to serialize fee")),
        ]
        .into_iter()
        .map(Attribute::from)
        .collect()
    }
}

pub struct PollMetadata {
    pub poll_id: PollId,
    pub source_chain: ChainName,
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
            (
                "expires_at",
                &value.expires_at.to_string(),
            ),
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



#[cw_serde]
pub struct TxEventConfirmation {
    pub transaction_hash: String,
    pub source_chain: ChainName,
    pub event_data: String, // JSON string representing the serialized EventData
}

// Message TryFrom implementation removed - message functionality has been removed

impl TryFrom<(crate::msg::EventToVerify, &MessageIdFormat)> for TxEventConfirmation {
    type Error = ContractError;
    fn try_from(
        (event, _msg_id_format): (crate::msg::EventToVerify, &MessageIdFormat),
    ) -> Result<Self, Self::Error> {
        // Parse the event_data to extract transaction_hash
        let event_data: event_verifier_api::EventData = serde_json::from_str(&event.event_data)
            .map_err(|_| ContractError::SerializationFailed)?;
        
        let transaction_hash = match event_data {
            event_verifier_api::EventData::Evm { transaction_hash, .. } => {
                transaction_hash.tx_hash_as_hex().to_string()
            }
        };
        
        Ok(TxEventConfirmation {
            transaction_hash,
            source_chain: event.source_chain,
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

// PollEnded event removed

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
                    transaction_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    source_chain: "sourceChain".try_into().unwrap(),
                    event_data: serde_json::to_string(&serde_json::json!({
                        "Evm": {
                            "transaction_details": null,
                            "events": [{
                                "contract_address": "contractAddress1",
                                "event_index": 1,
                                "topics": ["010203"],
                                "data": "01020304"
                            }]
                        }
                    })).unwrap(),
                },
                TxEventConfirmation {
                    transaction_hash: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                    source_chain: "sourceChain".try_into().unwrap(),
                    event_data: serde_json::to_string(&serde_json::json!({
                        "Evm": {
                            "transaction_details": null,
                            "events": [{
                                "contract_address": "contractAddress2",
                                "event_index": 2,
                                "topics": ["010203"],
                                "data": "05060708"
                            }]
                        }
                    })).unwrap(),
                },
            ],
            metadata: PollMetadata {
                poll_id: 1.into(),
                source_chain: "sourceChain".try_into().unwrap(),
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

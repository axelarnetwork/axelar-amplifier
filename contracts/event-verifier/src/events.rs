use std::vec::Vec;

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
        events: Vec<EventConfirmation>,
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
pub struct EventConfirmation {
    pub source_chain: ChainName,
    pub event_data: String, // JSON string representing the serialized EventData
}

impl From<crate::msg::EventToVerify> for EventConfirmation {
    fn from(event: crate::msg::EventToVerify) -> Self {
        EventConfirmation {
            source_chain: event.source_chain,
            event_data: event.event_data,
        }
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
                EventConfirmation {
                    source_chain: "sourceChain".try_into().unwrap(),
                    event_data: serde_json::to_string(&serde_json::json!({
                        "Evm": {
                            "events": [{
                                "contract_address": "contractAddress1",
                                "data": "01020304",
                                "event_index": 1,
                                "topics": ["010203"]
                            }],
                            "transaction_details": null
                        }
                    })).unwrap(),
                },
                EventConfirmation {
                    source_chain: "sourceChain".try_into().unwrap(),
                    event_data: serde_json::to_string(&serde_json::json!({
                        "Evm": {
                            "events": [{
                                "contract_address": "contractAddress2",
                                "data": "05060708",
                                "event_index": 2,
                                "topics": ["010203"]
                            }],
                            "transaction_details": null
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

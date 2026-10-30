use std::vec::Vec;

use axelar_wasm_std::voting::{PollId, Vote};
use axelar_wasm_std::{nonempty, VerificationStatus};
use cosmwasm_std::{Addr, Attribute, Event};
use router_api::ChainName;
use xrpl_types::msg::XRPLMessage;

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
    pub confirmation_height: u32,
    pub expires_at: u64,
    pub participants: Vec<Addr>,
}

pub enum PollStarted {
    Messages {
        messages: Vec<XRPLMessage>,
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

pub struct ExecutionDisabled;

impl From<ExecutionDisabled> for Event {
    fn from(_: ExecutionDisabled) -> Self {
        Event::new("execution_disabled")
    }
}

pub struct ExecutionEnabled;

impl From<ExecutionEnabled> for Event {
    fn from(_: ExecutionEnabled) -> Self {
        Event::new("execution_enabled")
    }
}

#[cfg(test)]
mod test {
    use axelar_wasm_std::msg_id::HexTxHash;
    use axelar_wasm_std::voting::Vote;
    use axelar_wasm_std::{nonempty, Threshold, VerificationStatus};
    use cosmwasm_std::testing::MockApi;
    use cosmwasm_std::Attribute;
    use serde_json::json;
    use xrpl_types::msg::{
        XRPLAddGasMessage, XRPLAddReservesMessage, XRPLCallContractMessage,
        XRPLInterchainTransferMessage, XRPLMessage,
    };
    use xrpl_types::types::XRPLPaymentAmount;

    use crate::events::{PollEnded, PollMetadata, PollStarted, QuorumReached, Voted};
    use crate::state::Config;

    #[test]
    fn events_should_not_change() {
        let api = MockApi::default();

        let config = Config {
            service_name: "serviceName".try_into().unwrap(),
            service_registry_contract: api.addr_make("serviceRegistry_contract"),
            source_gateway_address: "sourceGatewayAddress".try_into().unwrap(),
            voting_threshold: Threshold::try_from((2, 3)).unwrap().try_into().unwrap(),
            block_expiry: 10u64.try_into().unwrap(),
            confirmation_height: 1,
            source_chain: "sourceChain".try_into().unwrap(),
            rewards_contract: api.addr_make("rewardsContract"),
        };
        let event_instantiated =
            cosmwasm_std::Event::new("instantiated").add_attributes(<Vec<Attribute>>::from(config));

        let event_messages_poll_started: cosmwasm_std::Event = PollStarted::Messages {
            messages: vec![
                XRPLMessage::CallContractMessage(XRPLCallContractMessage {
                    tx_id: HexTxHash::new([0; 32]),
                    source_address: "raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo".parse().unwrap(),
                    destination_chain: "destinationChain".try_into().unwrap(),
                    destination_address: nonempty::String::try_from(
                        "95181d16cfb23Bc493668C17d973F061e30F2EAF",
                    )
                    .unwrap(),
                    payload_hash: [1; 32],
                    gas_fee_amount: XRPLPaymentAmount::Drops(100),
                }),
                XRPLMessage::InterchainTransferMessage(XRPLInterchainTransferMessage {
                    tx_id: HexTxHash::new([2; 32]),
                    source_address: "raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo".parse().unwrap(),
                    destination_chain: "destinationChain".try_into().unwrap(),
                    destination_address: nonempty::String::try_from(
                        "95181d16cfb23Bc493668C17d973F061e30F2EAF",
                    )
                    .unwrap(),
                    payload_hash: None,
                    transfer_amount: XRPLPaymentAmount::Drops(1000000),
                    gas_fee_amount: XRPLPaymentAmount::Drops(100),
                }),
                XRPLMessage::AddGasMessage(XRPLAddGasMessage {
                    tx_id: HexTxHash::new([3; 32]),
                    msg_id: HexTxHash::new([4; 32]),
                    amount: XRPLPaymentAmount::Drops(100000),
                    source_address: "raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo".parse().unwrap(),
                }),
                XRPLMessage::AddReservesMessage(XRPLAddReservesMessage {
                    tx_id: HexTxHash::new([5; 32]),
                    amount: 123456789,
                }),
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

        let event_quorum_reached: cosmwasm_std::Event = QuorumReached {
            content: "content".to_string(),
            status: VerificationStatus::NotFoundOnSourceChain,
            poll_id: 1.into(),
        }
        .into();

        let event_voted: cosmwasm_std::Event = Voted {
            poll_id: 1.into(),
            voter: api.addr_make("voter"),
            votes: vec![Vote::SucceededOnChain, Vote::FailedOnChain, Vote::NotFound],
        }
        .into();

        let event_poll_ended: cosmwasm_std::Event = PollEnded {
            poll_id: 1.into(),
            source_chain: "sourceChain".try_into().unwrap(),
            results: vec![
                Some(Vote::SucceededOnChain),
                Some(Vote::FailedOnChain),
                Some(Vote::NotFound),
                None,
            ],
        }
        .into();

        goldie::assert_json!(json!({
            "event_instantiated": event_instantiated,
            "event_messages_poll_started": event_messages_poll_started,
            "event_quorum_reached": event_quorum_reached,
            "event_voted": event_voted,
            "event_poll_ended": event_poll_ended,
        }));
    }
}

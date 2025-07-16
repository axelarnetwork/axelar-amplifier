use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::{try_from, Event};
use router_api::ChainName;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use stellar_xdr::curr::{ScAddress, ScBytes, ScString};
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::handlers::record_metrics::*;
use crate::monitoring;
use crate::stellar::rpc_client::Client;
use crate::stellar::verifier::verify_message;
use crate::types::TMAddress;

#[serde_as]
#[derive(Deserialize, Debug, Clone)]
pub struct Message {
    pub message_id: HexTxHashAndEventIndex,
    pub destination_address: ScString,
    pub destination_chain: ChainName,
    #[serde_as(as = "DisplayFromStr")]
    pub source_address: ScAddress,
    pub payload_hash: ScBytes,
}

#[serde_as]
#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    #[serde_as(as = "DisplayFromStr")]
    source_gateway_address: ScAddress,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

#[derive(Debug)]
pub struct Handler {
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    http_client: Client,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl Handler {
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        http_client: Client,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            http_client,
            latest_block_height,
            monitoring_client,
        }
    }

    fn vote_msg(&self, poll_id: PollId, votes: Vec<Vote>) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.as_ref().clone(),
            contract: self.voting_verifier_contract.as_ref().clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
                .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl EventHandler for Handler {
    type Err = Error;

    async fn handle(&self, event: &Event) -> error_stack::Result<Vec<Any>, Self::Err> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            source_gateway_address,
            messages,
            expires_at,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(DeserializeEvent)?,
        };

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        if *self.latest_block_height.borrow() >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let tx_hashes: HashSet<_> = messages
            .iter()
            .map(|message| message.message_id.tx_hash_as_hex_no_prefix().to_string())
            .collect();

        let handler_chain_name = "stellar";

        let transaction_responses = self
            .http_client
            .transaction_responses(tx_hashes)
            .await
            .change_context(Error::TxReceipts)?;

        let message_ids = messages
            .iter()
            .map(|message| message.message_id.to_string())
            .collect::<Vec<_>>();

        let votes = info_span!(
            "verify messages in poll",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            message_ids = message_ids.as_value()
        )
        .in_scope(|| {
            info!("ready to verify messages in poll",);

            let votes: Vec<_> = messages
                .iter()
                .map(|msg| {
                    transaction_responses
                        .get(&msg.message_id.tx_hash_as_hex_no_prefix().to_string())
                        .map_or(Vote::NotFound, |tx_response| {
                            verify_message(&source_gateway_address, tx_response, msg)
                        })
                })
                .inspect(|vote| {
                    record_vote_verifiction(&self.monitoring_client, vote, handler_chain_name);
                })
                .collect();
            info!(
                votes = votes.as_value(),
                "ready to vote for messages in poll"
            );

            votes
        });

        Ok(vec![self
            .vote_msg(poll_id, votes)
            .into_any()
            .expect("vote msg should serialize")])
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::net::SocketAddr;

    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use error_stack::Result;
    use ethers_core::types::H160;
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use stellar_xdr::curr::ScAddress;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::monitoring::metrics::Msg as MetricsMsg;
    use crate::monitoring::test_utils::create_test_monitoring_client;
    use crate::stellar::rpc_client::Client;
    use crate::types::TMAddress;
    use crate::{monitoring, PREFIX};

    #[test]
    fn should_not_deserialize_incorrect_event() {
        // incorrect event type
        let mut event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut event_type, ..
            } => {
                *event_type = "incorrect".into();
            }
            _ => panic!("incorrect event type"),
        }
        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            EventTypeMismatch(_)
        ));

        // invalid field
        let mut event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut attributes, ..
            } => {
                attributes.insert("source_gateway_address".into(), "invalid".into());
            }
            _ => panic!("incorrect event type"),
        }

        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            DeserializationFailed(_, _)
        ));
    }

    #[test]
    fn stellar_verify_msg_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: PollStartedEvent = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            Client::faux(),
            watch::channel(0).1,
            monitoring_client,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn verifier_is_not_a_participant() {
        let voting_verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &voting_verifier,
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            voting_verifier,
            Client::faux(),
            watch::channel(0).1,
            monitoring_client,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_vote_correctly() {
        let mut client = Client::faux();
        faux::when!(client.transaction_responses).then(|_| Ok(HashMap::new()));

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier,
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler = super::Handler::new(
            verifier,
            voting_verifier,
            client,
            watch::channel(0).1,
            monitoring_client,
        );

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_send_correct_vote_verification_messages() {
        let mut client = Client::faux();
        faux::when!(client.transaction_responses).then(|_| Ok(HashMap::new()));

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = create_test_monitoring_client();

        let handler = super::Handler::new(
            verifier,
            voting_verifier,
            client,
            watch::channel(0).1,
            monitoring_client,
        );

        let _ = handler.handle(&event).await.unwrap();

        for _ in 0..2 {
            let msg = receiver.recv().await.unwrap();
            assert_eq!(
                msg,
                MetricsMsg::VoteVerification {
                    vote_status: Vote::NotFound,
                    chain_name: "stellar".to_string(),
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "stellar".parse().unwrap(),
                source_gateway_address: ScAddress::Contract(stellar_xdr::curr::Hash::from([1; 32]))
                    .to_string()
                    .try_into()
                    .unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            messages: (0..2)
                .map(|i| {
                    let msg_id = HexTxHashAndEventIndex::new([3; 32], i as u64);
                    #[allow(deprecated)]
                    // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
                    TxEventConfirmation {
                        tx_id: msg_id.tx_hash_as_hex(),
                        event_index: u32::try_from(msg_id.event_index).unwrap(),
                        message_id: msg_id.to_string().parse().unwrap(),
                        source_address: ScAddress::Contract(stellar_xdr::curr::Hash::from([2; 32]))
                            .to_string()
                            .try_into()
                            .unwrap(),
                        destination_chain: "ethereum".parse().unwrap(),
                        destination_address: format!("0x{:x}", H160::repeat_byte(i))
                            .parse()
                            .unwrap(),
                        payload_hash: [i; 32],
                    }
                })
                .collect::<Vec<_>>(),
        }
    }
}

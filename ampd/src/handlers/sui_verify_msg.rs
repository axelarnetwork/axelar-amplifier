use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::Base58TxDigestAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::{try_from, Event};
use serde::Deserialize;
use sui_types::base_types::SuiAddress;
use tokio::sync::watch::Receiver;
use tracing::info;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::handlers::record_metrics::*;
use crate::monitoring;
use crate::sui::json_rpc::SuiClient;
use crate::sui::verifier::verify_message;
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub message_id: Base58TxDigestAndEventIndex,
    pub destination_address: String,
    pub destination_chain: router_api::ChainName,
    pub source_address: SuiAddress,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_gateway_address: SuiAddress,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

#[derive(Debug)]
pub struct Handler<C>
where
    C: SuiClient + Send + Sync,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl<C> Handler<C>
where
    C: SuiClient + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            rpc_client,
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
impl<C> EventHandler for Handler<C>
where
    C: SuiClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_gateway_address,
            messages,
            participants,
            expires_at,
            ..
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![]);
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");

            return Ok(vec![]);
        }

        let handler_chain_name = "sui";

        // Does not assume voting verifier emits unique tx ids.
        // RPC will throw an error if the input contains any duplicate, deduplicate tx ids to avoid unnecessary failures.
        let deduplicated_tx_ids: HashSet<_> = messages
            .iter()
            .map(|msg| msg.message_id.tx_digest.into())
            .collect();
        let transaction_blocks = self
            .rpc_client
            .finalized_transaction_blocks(deduplicated_tx_ids)
            .await
            .change_context(Error::TxReceipts)?;

        let votes = messages
            .iter()
            .map(|msg| {
                transaction_blocks
                    .get(&msg.message_id.tx_digest.into())
                    .map_or(Vote::NotFound, |tx_block| {
                        verify_message(&source_gateway_address, tx_block, msg)
                    })
            })
            .inspect(|vote| {
                record_vote_outcome(&self.monitoring_client, vote, handler_chain_name);
            })
            .collect();

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

    use axelar_wasm_std::msg_id::Base58TxDigestAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use cosmwasm_std;
    use error_stack::Report;
    use ethers_core::types::H160;
    use ethers_providers::ProviderError;
    use events::Event;
    use sui_types::base_types::{SuiAddress, SUI_ADDRESS_LENGTH};
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::handlers::errors::Error;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::monitoring;
    use crate::monitoring::metrics::Msg as MetricsMsg;
    use crate::monitoring::test_utils::create_test_monitoring_client;
    use crate::sui::json_rpc::MockSuiClient;
    use crate::types::TMAddress;

    const PREFIX: &str = "axelar";

    #[test]
    fn sui_verify_msg_should_deserialize_correct_event() {
        let event: PollStartedEvent = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into()
        .unwrap();

        goldie::assert_debug!(event);
    }

    // Should not handle event if it is not a poll started event
    #[async_test]
    async fn not_poll_started_event() {
        let event = into_structured_event(
            cosmwasm_std::Event::new("transfer"),
            &TMAddress::random(PREFIX),
        );

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            MockSuiClient::new(),
            watch::channel(0).1,
            monitoring_client,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    // Should not handle event if it is not emitted from voting verifier
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
            MockSuiClient::new(),
            watch::channel(0).1,
            monitoring_client,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    // Should not handle event if verifier is not a poll participant
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
            MockSuiClient::new(),
            watch::channel(0).1,
            monitoring_client,
        );

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn failed_to_get_finalized_tx_blocks() {
        let mut rpc_client = MockSuiClient::new();
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| {
                Err(Report::from(ProviderError::CustomError(
                    "failed to get tx blocks".to_string(),
                )))
            });

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
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(matches!(
            *handler.handle(&event).await.unwrap_err().current_context(),
            Error::TxReceipts
        ));
    }

    #[async_test]
    async fn should_vote_correctly() {
        let mut rpc_client = MockSuiClient::new();
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| Ok(HashMap::new()));

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
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_record_vote_outcome_metrics() {
        let mut rpc_client = MockSuiClient::new();
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| Ok(HashMap::new()));

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
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        let _ = handler.handle(&event).await.unwrap();

        let metric = receiver.recv().await.unwrap();
        assert_eq!(
            metric,
            MetricsMsg::VoteOutcome {
                vote_status: Vote::NotFound,
                chain_name: "sui".to_string(),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut rpc_client = MockSuiClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| {
                Err(Report::from(ProviderError::CustomError(
                    "failed to get finalized transaction blocks".to_string(),
                )))
            });

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let (_, monitoring_client) = monitoring::Server::new(None::<SocketAddr>).unwrap();

        let handler =
            super::Handler::new(verifier, voting_verifier, rpc_client, rx, monitoring_client);

        // poll is not expired yet, should hit rpc error
        assert!(handler.handle(&event).await.is_err());

        let _ = tx.send(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let msg_id = Base58TxDigestAndEventIndex::new([1; 32], 0u64);
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "sui".parse().unwrap(),
                source_gateway_address: SuiAddress::from_bytes([3; SUI_ADDRESS_LENGTH])
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            messages: vec![TxEventConfirmation {
                tx_id: msg_id.tx_digest_as_base58(),
                event_index: u32::try_from(msg_id.event_index).unwrap(),
                message_id: msg_id.to_string().parse().unwrap(),
                source_address: SuiAddress::from_bytes([4; SUI_ADDRESS_LENGTH])
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                destination_chain: "ethereum".parse().unwrap(),
                destination_address: format!("0x{:x}", H160::repeat_byte(3)).parse().unwrap(),
                payload_hash: [2; 32],
            }],
        }
    }
}

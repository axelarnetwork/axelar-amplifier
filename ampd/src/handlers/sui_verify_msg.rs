use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use serde::Deserialize;
use sui_types::base_types::{SuiAddress, TransactionDigest};

use axelar_wasm_std::voting::{PollId, Vote};
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use tokio::sync::watch::Receiver;
use tracing::info;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::sui::{json_rpc::SuiClient, verifier::verify_message};
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub tx_id: TransactionDigest,
    pub event_index: u64,
    pub destination_address: String,
    pub destination_chain: connection_router::state::ChainName,
    pub source_address: SuiAddress,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollId,
    source_gateway_address: SuiAddress,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler<C, B>
where
    C: SuiClient + Send + Sync,
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: C,
    broadcast_client: B,
    latest_block_height: Receiver<u64>,
}

impl<C, B> Handler<C, B>
where
    C: SuiClient + Send + Sync,
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: C,
        broadcast_client: B,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            rpc_client,
            broadcast_client,
            latest_block_height,
        }
    }
    async fn broadcast_votes(&self, poll_id: PollId, votes: Vec<Vote>) -> Result<()> {
        let msg = serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
            .expect("vote msg should serialize");
        let tx = MsgExecuteContract {
            sender: self.worker.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
            msg,
            funds: vec![],
        };

        self.broadcast_client
            .broadcast(tx)
            .await
            .change_context(Error::Broadcaster)
    }
}

#[async_trait]
impl<C, B> EventHandler for Handler<C, B>
where
    C: SuiClient + Send + Sync,
    B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<()> {
        let PollStartedEvent {
            contract_address,
            poll_id,
            source_gateway_address,
            messages,
            participants,
            expires_at,
            ..
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(());
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if self.voting_verifier != contract_address {
            return Ok(());
        }

        if !participants.contains(&self.worker) {
            return Ok(());
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(());
        }

        // Does not assume voting verifier emits unique tx ids.
        // RPC will throw an error if the input contains any duplicate, deduplicate tx ids to avoid unnecessary failures.
        let deduplicated_tx_ids: HashSet<_> = messages.iter().map(|msg| msg.tx_id).collect();
        let transaction_blocks = self
            .rpc_client
            .finalized_transaction_blocks(deduplicated_tx_ids)
            .await
            .change_context(Error::TxReceipts)?;

        let votes = messages
            .iter()
            .map(|msg| {
                transaction_blocks
                    .get(&msg.tx_id)
                    .map_or(Vote::NotFound, |tx_block| {
                        verify_message(&source_gateway_address, tx_block, msg)
                    })
            })
            .collect();

        self.broadcast_votes(poll_id, votes).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::TryInto;

    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmwasm_std;
    use error_stack::{Report, Result};
    use ethers::providers::ProviderError;
    use events::Event;
    use sui_types::base_types::{SuiAddress, TransactionDigest};
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::handlers::{errors::Error, tests::get_event};
    use crate::queue::queued_broadcaster;
    use crate::queue::queued_broadcaster::MockBroadcasterClient;
    use crate::sui::json_rpc::MockSuiClient;
    use crate::types::{EVMAddress, Hash, TMAddress};

    const PREFIX: &str = "axelar";

    #[test]
    fn should_deserialize_poll_started_event() {
        let event: Result<PollStartedEvent, events::Error> = get_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into();

        assert!(event.is_ok());
    }

    // Should not handle event if it is not a poll started event
    #[async_test]
    async fn not_poll_started_event() {
        let event = get_event(
            cosmwasm_std::Event::new("transfer"),
            &TMAddress::random(PREFIX),
        );

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            MockSuiClient::new(),
            MockBroadcasterClient::new(),
            watch::channel(0).1,
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if it is not emitted from voting verifier
    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = get_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            MockSuiClient::new(),
            MockBroadcasterClient::new(),
            watch::channel(0).1,
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if worker is not a poll participant
    #[async_test]
    async fn worker_is_not_a_participant() {
        let voting_verifier = TMAddress::random(PREFIX);
        let event = get_event(
            poll_started_event(participants(5, None), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            voting_verifier,
            MockSuiClient::new(),
            MockBroadcasterClient::new(),
            watch::channel(0).1,
        );

        assert!(handler.handle(&event).await.is_ok());
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
        let worker = TMAddress::random(PREFIX);

        let event = get_event(
            poll_started_event(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            rpc_client,
            MockBroadcasterClient::new(),
            watch::channel(0).1,
        );

        assert!(matches!(
            *handler.handle(&event).await.unwrap_err().current_context(),
            Error::TxReceipts
        ));
    }

    #[async_test]
    async fn failed_to_broadcast() {
        let mut rpc_client = MockSuiClient::new();
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| Ok(HashMap::new()));

        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast()
            .returning(move |_: MsgExecuteContract| {
                Err(Report::from(queued_broadcaster::Error::Broadcast))
            });

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let event = get_event(
            poll_started_event(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            rpc_client,
            broadcast_client,
            watch::channel(0).1,
        );

        assert!(matches!(
            *handler.handle(&event).await.unwrap_err().current_context(),
            Error::Broadcaster
        ));
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
        let broadcast_client = MockBroadcasterClient::new();

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = get_event(
            poll_started_event(participants(5, Some(worker.clone())), expiration),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler =
            super::Handler::new(worker, voting_verifier, rpc_client, broadcast_client, rx);

        // poll is not expired yet, should hit rpc error
        assert!(handler.handle(&event).await.is_err());

        let _ = tx.send(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert!(handler.handle(&event).await.is_ok());
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "sui".parse().unwrap(),
                source_gateway_address: SuiAddress::random_for_testing_only()
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
            messages: vec![TxEventConfirmation {
                tx_id: TransactionDigest::random().to_string().parse().unwrap(),
                event_index: 0,
                source_address: SuiAddress::random_for_testing_only()
                    .to_string()
                    .parse()
                    .unwrap(),
                destination_chain: "ethereum".parse().unwrap(),
                destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                payload_hash: Hash::random().to_fixed_bytes(),
            }],
        }
    }

    fn participants(n: u8, worker: Option<TMAddress>) -> Vec<TMAddress> {
        (0..n)
            .into_iter()
            .map(|_| TMAddress::random(PREFIX))
            .chain(worker.into_iter())
            .collect()
    }
}

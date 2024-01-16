use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use serde::Deserialize;
use sui_types::base_types::{SuiAddress, TransactionDigest};
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};

use axelar_wasm_std::voting::{PollId, Vote};
use connection_router::state::ID_SEPARATOR;
use cosmwasm_std::HexBinary;
use cosmwasm_std::Uint128;
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::sui::json_rpc::SuiClient;
use crate::sui::verifier::verify_worker_set;
use crate::types::TMAddress;

#[derive(Deserialize, Debug)]
pub struct Operators {
    pub weights_by_addresses: Vec<(HexBinary, Uint128)>,
    pub threshold: Uint128,
}

#[derive(Deserialize, Debug)]
pub struct WorkerSetConfirmation {
    pub tx_id: TransactionDigest,
    pub event_index: u64,
    pub operators: Operators,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-worker_set_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollId,
    source_gateway_address: SuiAddress,
    worker_set: WorkerSetConfirmation,
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
    async fn broadcast_vote(&self, poll_id: PollId, vote: Vote) -> error_stack::Result<(), Error> {
        let msg = serde_json::to_vec(&ExecuteMsg::Vote {
            poll_id,
            votes: vec![vote],
        })
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

    async fn handle(&self, event: &Event) -> error_stack::Result<(), Error> {
        let PollStartedEvent {
            contract_address,
            poll_id,
            source_gateway_address,
            worker_set,
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

        let transaction_block = self
            .rpc_client
            .finalized_transaction_block(worker_set.tx_id)
            .await
            .change_context(Error::TxReceipts)?;

        let vote = info_span!(
            "verify a new worker set for Sui",
            poll_id = poll_id.to_string(),
            id = format!(
                "0x{:x}{}{}",
                worker_set.tx_id, ID_SEPARATOR, worker_set.event_index
            )
        )
        .in_scope(|| {
            let vote = transaction_block.map_or(Vote::NotFound, |tx_receipt| {
                verify_worker_set(&source_gateway_address, &tx_receipt, &worker_set)
            });

            info!(
                vote = vote.as_value(),
                "ready to vote for a new worker set in poll"
            );

            vote
        });

        self.broadcast_vote(poll_id, vote).await
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use axelar_wasm_std::operators::Operators;
    use cosmwasm_std::HexBinary;
    use error_stack::{Report, Result};
    use ethers::providers::ProviderError;
    use events::Event;
    use sui_types::base_types::{SuiAddress, TransactionDigest};
    use tokio::sync::watch;
    use voting_verifier::events::{PollMetadata, PollStarted, WorkerSetConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::queue::queued_broadcaster::MockBroadcasterClient;
    use crate::sui::json_rpc::MockSuiClient;
    use crate::PREFIX;
    use crate::{handlers::tests::get_event, types::TMAddress};

    use tokio::test as async_test;

    #[test]
    fn should_deserialize_worker_set_poll_started_event() {
        let participants = (0..5)
            .into_iter()
            .map(|_| TMAddress::random(PREFIX))
            .collect();

        let event: Result<PollStartedEvent, events::Error> = get_event(
            worker_set_poll_started_event(participants, 100),
            &TMAddress::random(PREFIX),
        )
        .try_into();

        assert!(event.is_ok());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut rpc_client = MockSuiClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client
            .expect_finalized_transaction_block()
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
            worker_set_poll_started_event(vec![worker.clone()].into_iter().collect(), expiration),
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

    fn worker_set_poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        PollStarted::WorkerSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "sui".parse().unwrap(),
                source_gateway_address: SuiAddress::random_for_testing_only()
                    .to_string()
                    .parse()
                    .unwrap(),
                confirmation_height: 1,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            worker_set: WorkerSetConfirmation {
                tx_id: TransactionDigest::random().to_string().parse().unwrap(),
                event_index: 0,
                operators: Operators::new(
                    vec![
                        (
                            HexBinary::from(SuiAddress::random_for_testing_only().to_vec()),
                            1u64.into(),
                        ),
                        (
                            HexBinary::from(SuiAddress::random_for_testing_only().to_vec()),
                            1u64.into(),
                        ),
                        (
                            HexBinary::from(SuiAddress::random_for_testing_only().to_vec()),
                            1u64.into(),
                        ),
                    ],
                    2u64.into(),
                ),
            },
        }
    }
}

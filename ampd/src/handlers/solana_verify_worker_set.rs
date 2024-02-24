use std::convert::TryInto;

use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::info;

use async_trait::async_trait;
use events::Error::EventTypeMismatch;
use events_derive::try_from;

use axelar_wasm_std::voting::{PollId, Vote};
use connection_router::state::ChainName;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::solana::json_rpc::SolanaClient;
use crate::solana::ws_verifier::{parse_gateway_event, verify_worker_set};
use crate::types::{TMAddress, U256};

use gmp_gateway::events::GatewayEvent;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Operators {
    pub weights_by_addresses: Vec<(String, U256)>,
    pub threshold: U256,
}

#[derive(Deserialize, Debug)]
pub struct WorkerSetConfirmation {
    pub tx_id: String,
    pub event_index: u64,
    pub operators: Operators,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-worker_set_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    worker_set: WorkerSetConfirmation,
    poll_id: PollId,
    source_chain: connection_router::state::ChainName,
    source_gateway_address: String,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<TMAddress>,
}

pub struct Handler<C, B>
where
    C: SolanaClient + Send + Sync,
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    chain: ChainName,
    rpc_client: C,
    broadcast_client: B,
    latest_block_height: Receiver<u64>,
}

impl<C, B> Handler<C, B>
where
    C: SolanaClient + Send + Sync,
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        chain: ChainName,
        rpc_client: C,
        broadcast_client: B,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            chain,
            rpc_client,
            broadcast_client,
            latest_block_height,
        }
    }

    async fn broadcast_vote(&self, poll_id: PollId, vote: Vote) -> Result<()> {
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
    C: SolanaClient + Send + Sync,
    B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<()> {
        let PollStartedEvent {
            contract_address,
            poll_id,
            source_chain,
            source_gateway_address,
            expires_at,
            confirmation_height: _,
            participants,
            worker_set,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(())
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if self.voting_verifier != contract_address {
            return Ok(());
        }

        if self.chain != source_chain {
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

        let sol_tx = self
            .rpc_client
            .get_transaction(&worker_set.tx_id)
            .await
            .map_err(|_| Error::TxReceipts)?; // Todo, maybe we should check wether this is an empty response or a network failure. The later, should throw Error::TxReceipts. But if the RPC clients fails on a not found entity, we should probably emit Vote::FailedOnChain vote instead.

        let gw_event = parse_gateway_event(&sol_tx).map_err(|_| Error::DeserializeEvent)?;

        let pub_key = match gw_event {
            GatewayEvent::OperatorshipTransferred {
                info_account_address,
            } => info_account_address,
            _ => return self.broadcast_vote(poll_id, Vote::FailedOnChain).await,
        };

        let account_info = self
            .rpc_client
            .get_account_info(&pub_key.to_string())
            .await
            .map_err(|_| Error::TxReceipts)?; // Todo, maybe we should check wether this is an empty response or a network failure. The later, should throw Error::TxReceipts. But if the RPC clients fails on a not found entity, we should probably emit Vote::FailedOnChain vote instead.

        let vote =
            verify_worker_set(&source_gateway_address, &sol_tx, &worker_set, &account_info).await;
        self.broadcast_vote(poll_id, vote).await
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_wasm_std::{nonempty, operators::Operators};
    use cosmwasm_std::HexBinary;
    use prost::Message;
    use tokio::sync::watch;
    use voting_verifier::events::{PollMetadata, PollStarted, WorkerSetConfirmation};

    use crate::{
        handlers::tests::get_event, queue::queued_broadcaster::MockBroadcasterClient,
        solana::json_rpc::MockSolanaClient, PREFIX,
    };

    use tokio::test as async_test;

    use super::*;

    #[async_test]
    async fn must_abort_if_voting_verifier_is_same_as_contract_address() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let mut rpc_client = MockSolanaClient::new();
        rpc_client.expect_get_transaction().never();
        rpc_client.expect_get_account_info().never();

        let broadcast_client = MockBroadcasterClient::new();

        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        let handler = Handler::new(
            worker.clone(),
            voting_verifier.clone(),
            ChainName::from_str("solana").unwrap(),
            rpc_client,
            broadcast_client,
            rx,
        );

        let event = get_event(
            worker_set_poll_started_event(participants(2, Some(worker.clone())), expiration),
            &TMAddress::random(PREFIX),
        );

        handler.handle(&event).await.unwrap();
    }

    #[async_test]
    async fn must_abort_chain_does_not_match() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let mut rpc_client = MockSolanaClient::new();
        rpc_client.expect_get_transaction().never();
        rpc_client.expect_get_account_info().never();

        let broadcast_client = MockBroadcasterClient::new();
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        let handler = Handler::new(
            worker.clone(),
            voting_verifier.clone(),
            ChainName::from_str("not_matching_chain").unwrap(),
            rpc_client,
            broadcast_client,
            rx,
        );

        let event = get_event(
            worker_set_poll_started_event(participants(2, Some(worker.clone())), expiration),
            &voting_verifier,
        );

        handler.handle(&event).await.unwrap();
    }

    #[async_test]
    async fn must_abort_if_worker_is_not_participant() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let mut rpc_client = MockSolanaClient::new();
        rpc_client.expect_get_transaction().never();
        rpc_client.expect_get_account_info().never();

        let broadcast_client = MockBroadcasterClient::new();
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        let handler = Handler::new(
            worker.clone(),
            voting_verifier.clone(),
            ChainName::from_str("solana").unwrap(),
            rpc_client,
            broadcast_client,
            rx,
        );

        let event = get_event(
            worker_set_poll_started_event(participants(2, None), expiration), // worker is not here.
            &voting_verifier,
        );

        handler.handle(&event).await.unwrap();
    }

    #[async_test]
    async fn must_abort_on_expired_poll() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let mut rpc_client = MockSolanaClient::new();
        rpc_client.expect_get_transaction().never();
        rpc_client.expect_get_account_info().never();

        let broadcast_client = MockBroadcasterClient::new();
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration);

        let handler = Handler::new(
            worker.clone(),
            voting_verifier.clone(),
            ChainName::from_str("solana").unwrap(),
            rpc_client,
            broadcast_client,
            rx,
        );

        let event = get_event(
            worker_set_poll_started_event(participants(2, Some(worker.clone())), expiration),
            &voting_verifier,
        );

        handler.handle(&event).await.unwrap();
    }

    fn worker_set_poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        PollStarted::WorkerSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "solana".parse().unwrap(),
                source_gateway_address: nonempty::String::from_str(
                    "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756a",
                )
                .unwrap(),
                confirmation_height: 1,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            worker_set: WorkerSetConfirmation {
                tx_id: nonempty::String::from_str("value").unwrap(),
                event_index: 1,
                operators: Operators::new(
                    vec![(
                        HexBinary::from(
                            "03f57d1a813febaccbe6429603f9ec57969511b76cd680452dba91fa01f54e756d"
                                .to_string()
                                .encode_to_vec(),
                        ),
                        1u64.into(),
                    )],
                    2u64.into(),
                ),
            },
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

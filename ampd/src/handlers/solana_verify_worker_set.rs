use std::convert::TryInto;

use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use serde::Deserialize;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use std::str::FromStr;
use tokio::sync::watch::Receiver;
use tracing::{error, info};

use async_trait::async_trait;
use events::Error::EventTypeMismatch;
use events_derive::try_from;

use axelar_wasm_std::voting::{PollId, Vote};
use connection_router::state::ChainName;
use solana_client::nonblocking::rpc_client::RpcClient;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
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

pub struct Handler<B>
where
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    chain: ChainName,
    rpc_client: RpcClient,
    broadcast_client: B,
    latest_block_height: Receiver<u64>,
}

impl<B> Handler<B>
where
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        chain: ChainName,
        rpc_client: RpcClient,
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
        .map_err(|_| Error::Broadcaster)?;

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
impl<B> EventHandler for Handler<B>
where
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

        let sol_tx_signature = match Signature::from_str(&worker_set.tx_id) {
            Ok(sig) => sig,
            Err(err) => {
                error!(
                    poll_id = poll_id.to_string(),
                    err = err.to_string(),
                    "Cannot decode solana tx signature"
                );

                return self.broadcast_vote(poll_id, Vote::FailedOnChain).await;
            }
        };

        let sol_tx = match self
            .rpc_client
            .get_transaction(&sol_tx_signature, UiTransactionEncoding::Json)
            .await
        {
            Ok(tx) => tx,
            Err(err) => match err.kind() {
                solana_client::client_error::ClientErrorKind::SerdeJson(_) => {
                    return self.broadcast_vote(poll_id, Vote::NotFound).await
                }
                _ => return Err(Error::TxReceipts)?,
            },
        };

        let gw_event = parse_gateway_event(&sol_tx).map_err(|_| Error::DeserializeEvent)?;

        let pub_key = match gw_event {
            GatewayEvent::OperatorshipTransferred {
                info_account_address,
            } => info_account_address,
            _ => return self.broadcast_vote(poll_id, Vote::FailedOnChain).await,
        };

        let account_data = match self.rpc_client.get_account_data(&pub_key).await {
            Ok(data) => data,
            Err(err) => match err.kind() {
                solana_client::client_error::ClientErrorKind::SerdeJson(_) => {
                    return self.broadcast_vote(poll_id, Vote::FailedOnChain).await
                }
                _ => return Err(Error::TxReceipts)?,
            },
        };

        let vote =
            verify_worker_set(&source_gateway_address, &sol_tx, &worker_set, &account_data).await;
        self.broadcast_vote(poll_id, vote).await
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_wasm_std::{nonempty, operators::Operators};
    use cosmwasm_std::HexBinary;
    use prost::Message;
    use solana_client::rpc_request::RpcRequest;
    use tokio::sync::watch;
    use voting_verifier::events::{PollMetadata, PollStarted, WorkerSetConfirmation};

    use crate::{
        handlers::tests::get_event, queue::queued_broadcaster::MockBroadcasterClient,
        solana::test_utils::rpc_client_with_recorder, PREFIX,
    };

    use tokio::test as async_test;

    use super::*;

    #[async_test]
    async fn must_abort_if_voting_verifier_is_same_as_contract_address() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

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

        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
        );
    }

    #[async_test]
    async fn must_abort_chain_does_not_match() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

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

        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
        );
    }

    #[async_test]
    async fn must_abort_if_worker_is_not_participant() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

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

        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
        );
    }

    #[async_test]
    async fn must_abort_on_expired_poll() {
        let worker = TMAddress::random(PREFIX);
        let voting_verifier = TMAddress::random(PREFIX);

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

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

        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetAccountInfo)
        );
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
            .map(|_| TMAddress::random(PREFIX))
            .chain(worker)
            .collect()
    }
}

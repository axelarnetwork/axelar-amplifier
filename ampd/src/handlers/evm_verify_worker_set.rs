use std::convert::TryInto;

use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use ethers::types::{TransactionReceipt, U64};
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;

use async_trait::async_trait;
use events::Error::EventTypeMismatch;
use events_derive::try_from;

use axelar_wasm_std::voting::{PollId, Vote};
use connection_router::state::ID_SEPARATOR;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::evm::verifier::verify_worker_set;
use crate::evm::{finalizer, json_rpc::EthereumClient, ChainName};
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::types::{EVMAddress, Hash, TMAddress, U256};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Operators {
    pub weights_by_addresses: Vec<(EVMAddress, U256)>,
    pub threshold: U256,
}

#[derive(Deserialize, Debug)]
pub struct WorkerSetConfirmation {
    pub tx_id: Hash,
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
    source_gateway_address: EVMAddress,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<TMAddress>,
}

pub struct Handler<C, B>
where
    C: EthereumClient,
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
    C: EthereumClient + Send + Sync,
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

    async fn finalized_tx_receipt(
        &self,
        tx_hash: Hash,
        confirmation_height: u64,
    ) -> Result<Option<TransactionReceipt>> {
        let latest_finalized_block_height =
            finalizer::pick(&self.chain, &self.rpc_client, confirmation_height)
                .latest_finalized_block_height()
                .await
                .change_context(Error::Finalizer)?;
        let tx_receipt = self
            .rpc_client
            .transaction_receipt(tx_hash)
            .await
            .change_context(Error::Finalizer)?;

        Ok(tx_receipt.and_then(|tx_receipt| {
            if tx_receipt
                .block_number
                .unwrap_or(U64::MAX)
                .le(&latest_finalized_block_height)
            {
                Some(tx_receipt)
            } else {
                None
            }
        }))
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
    C: EthereumClient + Send + Sync,
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
            confirmation_height,
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

        let tx_receipt = self
            .finalized_tx_receipt(worker_set.tx_id, confirmation_height)
            .await?;
        let vote = info_span!(
            "verify a new worker set for an EVM chain",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            id = format!(
                "0x{:x}{}{}",
                worker_set.tx_id, ID_SEPARATOR, worker_set.event_index
            )
        )
        .in_scope(|| {
            info!("ready to verify a new worker set in poll");

            let vote = tx_receipt.map_or(Vote::NotFound, |tx_receipt| {
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

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use ethers::providers::ProviderError;
    use tendermint::abci;

    use axelar_wasm_std::operators::Operators;
    use cosmwasm_std::HexBinary;
    use events::Event;
    use voting_verifier::events::{PollMetadata, PollStarted, WorkerSetConfirmation};

    use crate::{
        event_processor::EventHandler,
        evm::{json_rpc::MockEthereumClient, ChainName},
        handlers::evm_verify_worker_set::PollStartedEvent,
        queue::queued_broadcaster::MockBroadcasterClient,
        types::{EVMAddress, Hash, TMAddress},
        PREFIX,
    };

    use error_stack::{Report, Result};
    use tokio::{sync::watch, test as async_test};

    #[test]
    fn should_deserialize_correct_event() {
        let event: Event = get_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: Result<PollStartedEvent, events::Error> = event.try_into();

        assert!(event.is_ok());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut rpc_client = MockEthereumClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client.expect_finalized_block().returning(|| {
            Err(Report::from(ProviderError::CustomError(
                "failed to get finalized block".to_string(),
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

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            ChainName::Ethereum,
            rpc_client,
            broadcast_client,
            rx,
        );

        // poll is not expired yet, should hit rpc error
        assert!(handler.handle(&event).await.is_err());

        let _ = tx.send(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert!(handler.handle(&event).await.is_ok());
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        PollStarted::WorkerSet {
            worker_set: WorkerSetConfirmation {
                tx_id: format!("0x{:x}", Hash::random()).parse().unwrap(),
                event_index: 100,
                operators: Operators::new(
                    vec![
                        (
                            HexBinary::from(EVMAddress::random().as_bytes()),
                            10u64.into(),
                        ),
                        (
                            HexBinary::from(EVMAddress::random().as_bytes()),
                            20u64.into(),
                        ),
                        (
                            HexBinary::from(EVMAddress::random().as_bytes()),
                            30u64.into(),
                        ),
                    ],
                    40u64.into(),
                ),
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "ethereum".parse().unwrap(),
                source_gateway_address: "0x4f4495243837681061c4743b74eedf548d5686a5"
                    .parse()
                    .unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
        }
    }

    fn get_event(event: impl Into<cosmwasm_std::Event>, contract_address: &TMAddress) -> Event {
        let mut event: cosmwasm_std::Event = event.into();

        event.ty = format!("wasm-{}", event.ty);
        event = event.add_attribute("_contract_address", contract_address.to_string());

        abci::Event::new(
            event.ty,
            event
                .attributes
                .into_iter()
                .map(|cosmwasm_std::Attribute { key, value }| {
                    (STANDARD.encode(key), STANDARD.encode(value))
                }),
        )
        .try_into()
        .unwrap()
    }

    fn participants(n: u8, worker: Option<TMAddress>) -> Vec<TMAddress> {
        (0..n)
            .into_iter()
            .map(|_| TMAddress::random(PREFIX))
            .chain(worker.into_iter())
            .collect()
    }
}

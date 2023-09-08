use std::convert::TryInto;

use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use ethers::types::{TransactionReceipt, U64};
use serde::Deserialize;
use tracing::{info, info_span};

use async_trait::async_trait;
use events::Error::EventTypeMismatch;
use events_derive::try_from;

use axelar_wasm_std::voting::PollID;
use connection_router::types::ID_SEPARATOR;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::evm::verifier::verify_worker_set;
use crate::evm::{json_rpc::EthereumClient, ChainName};
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
    pub log_index: u64,
    pub operators: Operators,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-worker_set_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    worker_set: WorkerSetConfirmation,
    poll_id: PollID,
    source_chain: connection_router::types::ChainName,
    source_gateway_address: EVMAddress,
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
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            chain,
            rpc_client,
            broadcast_client,
        }
    }

    async fn finalized_tx_receipt(
        &self,
        tx_hash: Hash,
        confirmation_height: u64,
    ) -> Result<Option<TransactionReceipt>> {
        let latest_finalized_block_height = self
            .chain
            .finalizer(&self.rpc_client, confirmation_height)
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

    async fn broadcast_vote(&self, poll_id: PollID, vote: bool) -> Result<()> {
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

        let tx_receipt = self
            .finalized_tx_receipt(worker_set.tx_id, confirmation_height)
            .await?;
        let vote = info_span!(
            "verify a new worker set for an EVM chain",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            id = format!(
                "0x{:x}{}{}",
                worker_set.tx_id, ID_SEPARATOR, worker_set.log_index
            )
        )
        .in_scope(|| {
            info!("ready to verify a new worker set in poll");

            let vote = tx_receipt.map_or(false, |tx_receipt| {
                verify_worker_set(&source_gateway_address, &tx_receipt, &worker_set)
            });
            info!(vote, "ready to vote for a new worker set in poll");

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
    use tendermint::abci;

    use axelar_wasm_std::operators::Operators;
    use cosmwasm_std::HexBinary;
    use events::Event;
    use voting_verifier::events::{PollMetadata, PollStarted, WorkerSetConfirmation};

    use crate::{
        handlers::evm_verify_worker_set::PollStartedEvent,
        types::{EVMAddress, Hash},
    };

    fn get_poll_started_event() -> Event {
        let poll_started = PollStarted::WorkerSet {
            worker_set: WorkerSetConfirmation {
                tx_id: format!("0x{:x}", Hash::random()),
                log_index: 100,
                operators: Operators {
                    threshold: 40u64.into(),
                    weights_by_addresses: vec![
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
                },
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "ethereum".parse().unwrap(),
                source_gateway_address: "0x4f4495243837681061c4743b74eedf548d5686a5".into(),
                confirmation_height: 15,
                expires_at: 100,
                participants: vec![
                    cosmwasm_std::Addr::unchecked(
                        "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7",
                    ),
                    cosmwasm_std::Addr::unchecked(
                        "axelarvaloper1tee73c83k2vqky9gt59jd3ztwxhqjm27l588q6",
                    ),
                    cosmwasm_std::Addr::unchecked(
                        "axelarvaloper1ds9z59d9szmxlzt6f8f6l6sgaenxdyd6095gcg",
                    ),
                ],
            },
        };

        let mut event: cosmwasm_std::Event = poll_started.into();
        event.ty = format!("wasm-{}", event.ty);
        event = event.add_attribute(
            "_contract_address",
            "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7",
        );

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

    #[test]
    fn should_deserialize_correct_event() {
        let event: Result<PollStartedEvent, _> = (&get_poll_started_event()).try_into();

        assert!(event.is_ok());
    }
}

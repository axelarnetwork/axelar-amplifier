use ampd::evm::finalizer::{self, Finalization};
use ampd::evm::json_rpc::EthereumClient;
use ampd::evm::verifier::verify_verifier_set;
use ampd::handlers::evm_verify_verifier_set::VerifierSetConfirmation;
use ampd::monitoring;
use ampd::monitoring::metrics;
use ampd::types::{EVMAddress, Hash};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
use error_stack::ResultExt;
use ethers_core::types::{TransactionReceipt, U64};
use events::{try_from, AbciEventTypeFilter, EventType};
use serde::Deserialize;
use tracing::{info, info_span};
use typed_builder::TypedBuilder;
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::Error;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
pub struct PollStartedEvent {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: EVMAddress,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<AccountId>,
}

#[derive(Debug, TypedBuilder)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    verifier: AccountId,
    voting_verifier_contract: AccountId,
    chain: ChainName,
    finalizer_type: Finalization,
    rpc_client: C,
    monitoring_client: monitoring::Client,
}

impl<C> Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    async fn finalized_tx_receipt(
        &self,
        tx_hash: Hash,
        confirmation_height: u64,
    ) -> Result<Option<TransactionReceipt>> {
        let latest_finalized_block_height =
            finalizer::pick(&self.finalizer_type, &self.rpc_client, confirmation_height)
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

    fn vote_msg(&self, poll_id: PollId, vote: Vote) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.clone(),
            contract: self.voting_verifier_contract.clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote {
                poll_id,
                votes: vec![vote],
            })
            .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    type Err = Error;
    type Event = PollStartedEvent;

    async fn handle<HC: EventHandlerClient + Send + 'static>(
        &self,
        event: PollStartedEvent,
        client: &mut HC,
    ) -> Result<Vec<Any>> {
        let PollStartedEvent {
            poll_id,
            source_chain,
            source_gateway_address,
            expires_at,
            confirmation_height,
            participants,
            verifier_set,
        } = event;

        if self.chain != source_chain {
            return Ok(vec![]);
        }

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = client
            .latest_block_height()
            .await
            .change_context(Error::EventHandling)?;
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let tx_receipt = self
            .finalized_tx_receipt(verifier_set.message_id.tx_hash.into(), confirmation_height)
            .await?;

        let vote = info_span!(
            "verify a new verifier set for an EVM chain",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            id = verifier_set.message_id.to_string()
        )
        .in_scope(|| {
            info!("ready to verify a new verifier set in poll");

            let vote = tx_receipt.map_or(Vote::NotFound, |tx_receipt| {
                verify_verifier_set(&source_gateway_address, &tx_receipt, &verifier_set)
            });

            self.monitoring_client
                .metrics()
                .record_metric(metrics::Msg::VerificationVote {
                    vote_decision: vote.clone(),
                    chain_name: self.chain.clone(),
                });

            info!(
                vote = vote.as_value(),
                "ready to vote for a new verifier set in poll"
            );

            vote
        });

        Ok(vec![self
            .vote_msg(poll_id, vote)
            .into_any()
            .expect("vote msg should serialize")])
    }

    fn subscription_params(&self) -> SubscriptionParams {
        SubscriptionParams::new(
            vec![AbciEventTypeFilter {
                event_type: PollStartedEvent::event_type(),
                contract: self.voting_verifier_contract.clone(),
            }], // TODO: Add verifier set poll started event filter?
            false,
        )
    }
}

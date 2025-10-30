use ampd::evm::finalizer::Finalization;
use ampd::evm::json_rpc::EthereumClient;
use ampd::evm::verifier::verify_verifier_set;
use ampd::handlers::evm_verify_verifier_set::VerifierSetConfirmation;
use ampd::monitoring;
use ampd::monitoring::metrics;
use ampd::types::EVMAddress;
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
use error_stack::ResultExt;
use events::{try_from, EventType};
use serde::Deserialize;
use tracing::{info, info_span};
use typed_builder::TypedBuilder;
use valuable::Valuable;

use crate::{common, Error};

type Result<T> = common::Result<T>;

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

        let tx_hash: ampd::types::Hash = verifier_set.message_id.tx_hash.into();
        let tx_receipts = common::finalized_tx_receipts(
            &self.rpc_client,
            &self.finalizer_type,
            [tx_hash],
            confirmation_height,
        )
        .await?;
        let tx_receipt = tx_receipts.get(&tx_hash).cloned();

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

        Ok(vec![common::vote_msg(
            &self.verifier,
            &self.voting_verifier_contract,
            poll_id,
            vec![vote],
        )
        .into_any()
        .expect("vote msg should serialize")])
    }

    fn subscription_params(&self) -> SubscriptionParams {
        common::subscription_params(
            &self.voting_verifier_contract,
            PollStartedEvent::event_type(),
        )
    }
}

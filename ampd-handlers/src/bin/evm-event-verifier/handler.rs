use ampd::evm::finalizer::Finalization;
use ampd::evm::json_rpc::EthereumClient;
use ampd::monitoring;
use ampd_handlers::voting::Error;
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
use error_stack::{Result, ResultExt};
use events::{AbciEventTypeFilter, EventType};
use tracing::{info, info_span};
use typed_builder::TypedBuilder;

use ampd::handlers::evm_verify_event::{
    create_vote_msg, deserialize_event_data, fetch_finalized_tx_receipts, should_skip_poll,
    verify_and_vote_on_events, PollStartedEvent,
};

#[derive(Debug, TypedBuilder)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    pub verifier: AccountId,
    pub event_verifier_contract: AccountId,
    pub chain: ChainName,
    pub finalizer_type: Finalization,
    pub confirmation_height: u64,
    pub rpc_client: C,
    pub monitoring_client: monitoring::Client,
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
    ) -> Result<Vec<Any>, Self::Err> {
        let PollStartedEvent {
            events: events_to_verify,
            poll_id,
            source_chain,
            expires_at,
            participants,
        } = event;

        let latest_block_height = client
            .latest_block_height()
            .await
            .change_context(Error::VotingEligibility)?;
        
        if should_skip_poll(
            &self.chain,
            &source_chain,
            &self.verifier,
            &participants,
            latest_block_height,
            expires_at,
            &poll_id,
        ) {
            return Ok(vec![]);
        }

        let events_data = deserialize_event_data(&events_to_verify);

        let finalized_tx_receipts = fetch_finalized_tx_receipts(
            &self.rpc_client,
            &self.finalizer_type,
            &events_data,
            self.confirmation_height,
        )
        .await
        .change_context(Error::FinalizedTxs)?;

        let poll_id_str: String = poll_id.to_string();
        let source_chain_str: String = source_chain.to_string();

        let votes = info_span!(
            "verify events from an EVM chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            event_count = events_to_verify.len(),
        )
        .in_scope(|| {
            info!("ready to verify events in poll");
            verify_and_vote_on_events(
                &events_data,
                &finalized_tx_receipts,
                &self.monitoring_client,
                &self.chain,
            )
        });

        Ok(vec![create_vote_msg(&self.verifier, &self.event_verifier_contract, poll_id, votes)
            .into_any()
            .expect("vote msg should serialize")])
    }

    fn subscription_params(&self) -> SubscriptionParams {
        SubscriptionParams::new(
            vec![AbciEventTypeFilter {
                event_type: PollStartedEvent::event_type(),
                contract: self.event_verifier_contract.clone(),
            }],
            false,
        )
    }
}


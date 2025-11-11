use ampd::evm::finalizer::Finalization;
use ampd::evm::json_rpc::EthereumClient;
use ampd::monitoring;
use ampd_handlers::voting::Error;
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::PollId;
use cosmrs::{AccountId, Any};
use error_stack::Result;
use event_verifier_api::EventToVerify;
use events::{try_from, AbciEventTypeFilter, Event, EventType};
use serde::Deserialize;
use typed_builder::TypedBuilder;

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-events_poll_started")]
pub struct EventsPollStarted {
    events: Vec<EventToVerify>,
    poll_id: PollId,
    source_chain: ChainName,
    expires_at: u64,
    participants: Vec<AccountId>,
}

#[derive(Debug, TypedBuilder)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    pub verifier: AccountId,
    pub event_verifier_contract: AccountId,
    pub chain: ChainName,
    pub finalizer_type: Finalization,
    pub rpc_client: C,
    pub monitoring_client: monitoring::Client,
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    type Err = Error;
    type Event = EventsPollStarted;

    async fn handle<HC: EventHandlerClient + Send + 'static>(
        &self,
        _event: EventsPollStarted,
        _client: &mut HC,
    ) -> Result<Vec<Any>, Self::Err> {
        // TODO: Implement event verification logic
        todo!("Event verification logic not yet implemented")
    }

    fn subscription_params(&self) -> SubscriptionParams {
        SubscriptionParams::new(
            vec![AbciEventTypeFilter {
                event_type: EventsPollStarted::event_type(),
                contract: self.event_verifier_contract.clone(),
            }],
            false,
        )
    }
}


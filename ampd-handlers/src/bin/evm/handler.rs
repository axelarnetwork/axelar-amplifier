use ampd::evm::finalizer::Finalization;
use ampd::evm::json_rpc::EthereumClient;
use ampd::monitoring;
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use cosmrs::{AccountId, Any};
use error_stack::{Report, ResultExt};
use events::{AbciEventTypeFilter, Event, EventType};
use serde::Deserialize;
use typed_builder::TypedBuilder;

use crate::messages_handler::{handle_messages, MessagesPollStarted};
use crate::verifier_set_handler::{handle_verifier_set, VerifierSetPollStarted};
use crate::{common, Error};

type Result<T> = common::Result<T>;

#[derive(Clone, Debug, Deserialize)]
pub enum PollStartedEvent {
    Messages(MessagesPollStarted),
    VerifierSet(VerifierSetPollStarted),
}

impl TryFrom<Event> for PollStartedEvent {
    type Error = Report<events::Error>;

    fn try_from(event: Event) -> std::result::Result<Self, Self::Error> {
        match event.clone() {
            Event::Abci {
                event_type,
                attributes: _,
            } if event_type == *MessagesPollStarted::event_type() => {
                Ok(PollStartedEvent::Messages(event.try_into()?))
            }
            Event::Abci {
                event_type,
                attributes: _,
            } if event_type == *VerifierSetPollStarted::event_type() => {
                Ok(PollStartedEvent::VerifierSet(event.try_into()?))
            }
            _ => Err(events::Error::EventTypeMismatch(format!(
                "{}/{}",
                MessagesPollStarted::event_type(),
                VerifierSetPollStarted::event_type()
            )))
            .attach_printable(format!("{{ event = {event:?} }}")),
        }
    }
}

#[derive(Debug, TypedBuilder)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    pub verifier: AccountId,
    pub voting_verifier_contract: AccountId,
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
    type Event = PollStartedEvent;

    async fn handle<HC: EventHandlerClient + Send + 'static>(
        &self,
        event: PollStartedEvent,
        client: &mut HC,
    ) -> Result<Vec<Any>> {
        match event {
            PollStartedEvent::Messages(event) => handle_messages(self, event, client).await,
            PollStartedEvent::VerifierSet(event) => handle_verifier_set(self, event, client).await,
        }
    }

    fn subscription_params(&self) -> SubscriptionParams {
        SubscriptionParams::new(
            vec![
                AbciEventTypeFilter {
                    event_type: MessagesPollStarted::event_type(),
                    contract: self.voting_verifier_contract.clone(),
                },
                AbciEventTypeFilter {
                    event_type: VerifierSetPollStarted::event_type(),
                    contract: self.voting_verifier_contract.clone(),
                },
            ],
            false,
        )
    }
}

use std::collections::{HashMap, HashSet};

use ampd::monitoring;
use ampd::sui::json_rpc::SuiClient;
use ampd::handlers::sui_verify_msg::Message;
use ampd::handlers::sui_verify_verifier_set::VerifierSetConfirmation;
use ampd_handlers::voting::{self, Error, PollEventData as _, VotingHandler};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::Base58TxDigestAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::{AccountId, Any};
use error_stack::{Report, ResultExt};
use events::{try_from, AbciEventTypeFilter, Event, EventType};
use serde::Deserialize;
use sui_json_rpc_types::SuiTransactionBlockResponse;
use sui_types::base_types::SuiAddress;
use sui_types::digests::TransactionDigest;
use typed_builder::TypedBuilder;

use crate::sui::verifier::{verify_message, verify_verifier_set};

pub type Result<T> = error_stack::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-messages_poll_started")]
pub struct MessagesPollStarted {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: SuiAddress,
    confirmation_height: u64,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<AccountId>,
}

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-verifier_set_poll_started")]
pub struct VerifierSetPollStarted {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: SuiAddress,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<AccountId>,
}

#[derive(Clone, Debug)]
pub enum PollEventData {
    Message(Message),
    VerifierSet(VerifierSetConfirmation),
}

impl voting::PollEventData for PollEventData {
    type Digest = TransactionDigest;
    type MessageId = Base58TxDigestAndEventIndex;
    type ChainAddress = SuiAddress;
    type Receipt = SuiTransactionBlockResponse;

    fn tx_hash(&self) -> axelar_wasm_std::hash::Hash {
        self.message_id().tx_hash
    }

    fn message_id(&self) -> &Base58TxDigestAndEventIndex {
        match self {
            PollEventData::Message(message) => &message.message_id,
            PollEventData::VerifierSet(verifier_set) => &verifier_set.message_id,
        }
    }

    fn verify(&self, source_gateway_address: &SuiAddress, tx_receipt: &SuiTransactionBlockResponse) -> Vote {
        match self {
            PollEventData::Message(message) => {
                verify_message(source_gateway_address, tx_receipt, message)
            }
            PollEventData::VerifierSet(verifier_set) => {
                verify_verifier_set(source_gateway_address, tx_receipt, verifier_set)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum PollStartedEvent {
    Messages(MessagesPollStarted),
    VerifierSet(VerifierSetPollStarted),
}

impl TryFrom<Event> for PollStartedEvent {
    type Error = Report<events::Error>;

    fn try_from(event: Event) -> std::result::Result<Self, Self::Error> {
        if let Ok(event) = MessagesPollStarted::try_from(event.clone()) {
            Ok(PollStartedEvent::Messages(event))
        } else if let Ok(event) = VerifierSetPollStarted::try_from(event.clone()) {
            Ok(PollStartedEvent::VerifierSet(event))
        } else {
            Err(events::Error::EventTypeMismatch(format!(
                "{}/{}",
                MessagesPollStarted::event_type(),
                VerifierSetPollStarted::event_type()
            )))
            .attach_printable(format!("{{ event = {event:?} }}"))
        }
    }
}

impl From<PollStartedEvent> for voting::PollStartedEvent<PollEventData, SuiAddress> {
    fn from(event: PollStartedEvent) -> Self {
        match event {
            PollStartedEvent::Messages(message_event) => voting::PollStartedEvent {
                poll_data: message_event
                    .messages
                    .into_iter()
                    .map(PollEventData::Message)
                    .collect(),
                poll_id: message_event.poll_id,
                source_chain: message_event.source_chain,
                source_gateway_address: message_event.source_gateway_address,
                expires_at: message_event.expires_at,
                confirmation_height: message_event.confirmation_height,
                participants: message_event.participants,
            },
            PollStartedEvent::VerifierSet(verifier_set_event) => voting::PollStartedEvent {
                poll_data: vec![PollEventData::VerifierSet(verifier_set_event.verifier_set)],
                poll_id: verifier_set_event.poll_id,
                source_chain: verifier_set_event.source_chain,
                source_gateway_address: verifier_set_event.source_gateway_address,
                expires_at: verifier_set_event.expires_at,
                confirmation_height: verifier_set_event.confirmation_height,
                participants: verifier_set_event.participants,
            },
        }
    }
}

#[derive(Debug, TypedBuilder)]
pub struct Handler<C>
where
    C: SuiClient,
{
    pub verifier: AccountId,
    pub voting_verifier_contract: AccountId,
    pub chain: ChainName,
    pub rpc_client: C,
    pub monitoring_client: monitoring::Client,
}

#[async_trait]
impl<C> VotingHandler for Handler<C>
where
    C: SuiClient + Send + Sync,
{
    type Digest = TransactionDigest;
    type Receipt = SuiTransactionBlockResponse;
    type ChainAddress = SuiAddress;
    type EventData = PollEventData;

    fn chain(&self) -> &ChainName {
        &self.chain
    }

    fn verifier(&self) -> &AccountId {
        &self.verifier
    }

    fn voting_verifier_contract(&self) -> &AccountId {
        &self.voting_verifier_contract
    }

    fn monitoring_client(&self) -> &monitoring::Client {
        &self.monitoring_client
    }

    async fn finalized_txs(
        &self,
        poll_data: &[Self::EventData],
        _confirmation_height: Option<u64>,
    ) -> Result<HashMap<Self::Digest, Self::Receipt>> {
        // Does not assume voting verifier emits unique tx ids.
        // RPC will throw an error if the input contains any duplicate, deduplicate tx ids to avoid unnecessary failures.
        let deduplicated_tx_ids: HashSet<_> = poll_data.iter().map(|data| data.tx_hash()).collect();

        let transaction_blocks = self
            .rpc_client
            .finalized_transaction_blocks(deduplicated_tx_ids)
            .await
            .change_context(Error::FinalizedTxs)
            .attach_printable("failed to get finalized transaction blocks")?;

        // TODO: parse tx blocks?

        Ok(transaction_blocks)
    }
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: SuiClient + Send + Sync,
{
    type Err = Error;
    type Event = PollStartedEvent;

    async fn handle<HC: EventHandlerClient + Send + 'static>(
        &self,
        event: PollStartedEvent,
        client: &mut HC,
    ) -> Result<Vec<Any>> {
        VotingHandler::handle(self, event.into(), client).await
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

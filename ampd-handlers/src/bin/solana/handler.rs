use std::fmt;
use std::fmt::Debug;
use std::collections::HashMap;

use ampd::handlers::solana_verify_msg::Message;
use ampd::handlers::solana_verify_verifier_set::VerifierSetConfirmation;
use ampd::monitoring;
use ampd::solana::msg_verifier::verify_message;
use ampd::solana::verifier_set_verifier::verify_verifier_set;
use ampd::solana::{SolanaRpcClientProxy, SolanaTransaction};
use ampd_handlers::voting::{self, Error, PollEventData as _, VotingHandler};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::AccountId;
use error_stack::{Report, ResultExt};
use events::{try_from, Event, EventType};
use serde::Deserialize;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use typed_builder::TypedBuilder;

pub type Result<T> = error_stack::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-messages_poll_started")]
pub struct MessagesPollStarted {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: String,
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
    source_gateway_address: String,
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
    type Digest = Signature;
    type MessageId = Base58SolanaTxSignatureAndEventIndex;
    type ChainAddress = Pubkey;
    type Receipt = SolanaTransaction;

    fn tx_hash(&self) -> Self::Digest {
        match self {
            PollEventData::Message(message) => message.message_id.raw_signature.into(),
            PollEventData::VerifierSet(verifier_set) => {
                verifier_set.message_id.raw_signature.into()
            }
        }
    }

    fn message_id(&self) -> &Self::MessageId {
        match self {
            PollEventData::Message(message) => &message.message_id,
            PollEventData::VerifierSet(verifier_set) => &verifier_set.message_id,
        }
    }

    fn verify(&self, source_gateway_address: &Pubkey, tx_receipt: &SolanaTransaction) -> Vote {
        match self {
            PollEventData::Message(message) => {
                verify_message(tx_receipt, message, source_gateway_address)
            }
            PollEventData::VerifierSet(verifier_set) => {
                // TODO: fix domain_separator
                let domain_separator: [u8; 32] = [42; 32];

                verify_verifier_set(
                    tx_receipt,
                    &verifier_set,
                    &domain_separator,
                    source_gateway_address,
                )
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

impl From<PollStartedEvent> for voting::PollStartedEvent<PollEventData, Pubkey> {
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
                source_gateway_address: message_event.source_gateway_address.parse().unwrap(),
                expires_at: message_event.expires_at,
                confirmation_height: message_event.confirmation_height,
                participants: message_event.participants,
            },
            PollStartedEvent::VerifierSet(verifier_set_event) => voting::PollStartedEvent {
                poll_data: vec![PollEventData::VerifierSet(verifier_set_event.verifier_set)],
                poll_id: verifier_set_event.poll_id,
                source_chain: verifier_set_event.source_chain,
                source_gateway_address: verifier_set_event.source_gateway_address.parse().unwrap(),
                expires_at: verifier_set_event.expires_at,
                confirmation_height: verifier_set_event.confirmation_height,
                participants: verifier_set_event.participants,
            },
        }
    }
}

#[allow(dead_code)]
#[derive(TypedBuilder)]
pub struct Handler<C>
where
    C: SolanaRpcClientProxy,
{
    pub verifier: AccountId,
    pub voting_verifier_contract: AccountId,
    pub chain: ChainName,
    pub gateway_address: Pubkey,
    // #[allow(dead_code)] TODO: fix domain separator
    pub domain_separator: [u8; 32],
    pub rpc_client: C,
    pub monitoring_client: monitoring::Client,
}

#[async_trait]
impl<C> VotingHandler for Handler<C>
where
    C: SolanaRpcClientProxy + Send + Sync,
{
    type Digest = Signature;
    type Receipt = SolanaTransaction;
    type ChainAddress = Pubkey;
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
        let tx_calls = poll_data.iter().map(|data| async {
            let signature = data.tx_hash();
            self.rpc_client
                .tx(&signature)
                .await
                .map(|tx| (signature, tx))
        });

        let finalized_tx_receipts: HashMap<Signature, SolanaTransaction> =
            futures::future::join_all(tx_calls)
                .await
                .into_iter()
                .flatten()
                .collect::<HashMap<Signature, SolanaTransaction>>();

        Ok(finalized_tx_receipts)
    }
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: SolanaRpcClientProxy + Send + Sync,
{
    type Err = Error;
    type Event = PollStartedEvent;

    async fn handle<HC: EventHandlerClient + Send + 'static>(
        &self,
        event: PollStartedEvent,
        client: &mut HC,
    ) -> Result<Vec<cosmrs::Any>> {
        VotingHandler::handle(self, event.into(), client).await
    }

    fn subscription_params(&self) -> SubscriptionParams {
        use events::AbciEventTypeFilter;

        SubscriptionParams::new(
            vec![
                AbciEventTypeFilter {
                    event_type: MessagesPollStarted::event_type(),
                    contract: self.voting_verifier_contract.clone(),
                    attributes: Default::default(),
                },
                AbciEventTypeFilter {
                    event_type: VerifierSetPollStarted::event_type(),
                    contract: self.voting_verifier_contract.clone(),
                    attributes: Default::default(),
                },
            ],
            false,
        )
    }
}

impl<C> Debug for Handler<C> 
where
    C: SolanaRpcClientProxy + Send + Sync,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handler")
            .field("verifier", &self.verifier)
            .field("voting_verifier_contract", &self.voting_verifier_contract)
            .field("gateway_address", &self.gateway_address)
            .field("rpc_client", &"WARN: Solana sdk does impl Debug")
            .field("monitoring_client", &self.monitoring_client)
            .finish()
    }
}

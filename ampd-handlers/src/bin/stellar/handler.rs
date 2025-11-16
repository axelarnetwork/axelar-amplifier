use std::collections::HashMap;

use ampd::handlers::stellar_verify_msg::Message;
use ampd::handlers::stellar_verify_verifier_set::VerifierSetConfirmation;
use ampd::monitoring;
use ampd::stellar::json_rpc::StellarClient;
use ampd::stellar::rpc_client::TxResponse;
use ampd::stellar::verifier::{verify_message, verify_verifier_set};
use ampd_handlers::voting::{self, Error, PollEventData as _, VotingHandler};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::{AccountId, Any};
use cosmwasm_std::HexBinary;
use error_stack::{Report, ResultExt};
use events::{try_from, AbciEventTypeFilter, Event, EventType};
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use stellar_xdr::curr::ScAddress;
use typed_builder::TypedBuilder;

pub type Result<T> = error_stack::Result<T, Error>;

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-messages_poll_started")]
pub struct MessagesPollStarted {
    poll_id: PollId,
    source_chain: ChainName,
    #[serde_as(as = "DisplayFromStr")]
    source_gateway_address: ScAddress,
    confirmation_height: u64,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<AccountId>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-verifier_set_poll_started")]
pub struct VerifierSetPollStarted {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: ChainName,
    #[serde_as(as = "DisplayFromStr")]
    source_gateway_address: ScAddress,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<AccountId>,
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
            Err(Report::new(events::Error::EventTypeMismatch(format!(
                "{}/{}",
                MessagesPollStarted::event_type(),
                VerifierSetPollStarted::event_type()
            )))
            .attach_printable(format!("{{ event = {event:?} }}")))
        }
    }
}

#[derive(Clone, Debug)]
pub enum PollEventData {
    Message(Message),
    VerifierSet(VerifierSetConfirmation),
}

impl voting::PollEventData for PollEventData {
    type Digest = Hash;
    type MessageId = HexTxHashAndEventIndex;
    type ChainAddress = ScAddress;
    type Receipt = TxResponse;

    fn tx_hash(&self) -> Self::Digest {
        match self {
            PollEventData::Message(message) => message.message_id.tx_hash,
            PollEventData::VerifierSet(verifier_set) => verifier_set.message_id.tx_hash,
        }
    }

    fn message_id(&self) -> &Self::MessageId {
        match self {
            PollEventData::Message(message) => &message.message_id,
            PollEventData::VerifierSet(verifier_set) => &verifier_set.message_id,
        }
    }

    fn verify(
        &self,
        source_gateway_address: &Self::ChainAddress,
        tx_receipt: &Self::Receipt,
    ) -> Vote {
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

impl From<PollStartedEvent> for voting::PollStartedEvent<PollEventData, ScAddress> {
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
    C: StellarClient,
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
    C: StellarClient + Send + Sync,
{
    type Digest = Hash;
    type Receipt = TxResponse;
    type ChainAddress = ScAddress;
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
        let tx_hashes = poll_data
            .iter()
            .map(|data| data.message_id().tx_hash_as_hex_no_prefix().to_string())
            .collect();

        let transaction_responses = self
            .rpc_client
            .transaction_responses(tx_hashes)
            .await
            .change_context(Error::FinalizedTxs)
            .attach_printable("failed to get transaction responses from Stellar RPC")?;

        Ok(transaction_responses
            .into_iter()
            .map(|(tx_hash_str, tx_response)| {
                let tx_hash = HexBinary::from_hex(&tx_hash_str)
                    .map(|hb| hb.as_slice().try_into().unwrap_or([0; 32]))
                    .unwrap_or([0; 32]);
                (tx_hash, tx_response)
            })
            .collect())
    }
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: StellarClient + Send + Sync,
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::TryInto;

    use ampd::handlers::test_utils::{into_structured_event, participants};
    use ampd::monitoring;
    use ampd::stellar::json_rpc::MockStellarClient;
    use ampd::types::TMAddress;
    use ampd_sdk::event::event_handler::EventHandler;
    use ampd_sdk::grpc::client::test_utils::MockHandlerTaskClient;
    use axelar_wasm_std::chain_name;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use ethers_core::types::H160;
    use events::Error::EventTypeMismatch;
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ed25519_test_data};
    use stellar_xdr::curr::ScAddress;
    use tokio::test as async_test;
    use voting_verifier::events::{
        PollMetadata, PollStarted, TxEventConfirmation, VerifierSetConfirmation,
    };

    use super::{Handler, MessagesPollStarted, VerifierSetPollStarted};

    const PREFIX: &str = "axelar";
    const STELLAR: &str = "stellar";

    fn message_poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let msg_ids = [
            HexTxHashAndEventIndex::new([1u8; 32], 0u64),
            HexTxHashAndEventIndex::new([2u8; 32], 1u64),
            HexTxHashAndEventIndex::new([3u8; 32], 10u64),
        ];
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!(STELLAR),
                source_gateway_address: ScAddress::Contract(
                    stellar_xdr::curr::Hash::from([1; 32]).into(),
                )
                .to_string()
                .parse()
                .unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            messages: vec![
                TxEventConfirmation {
                    message_id: msg_ids[0].to_string().parse().unwrap(),
                    source_address: ScAddress::Contract(
                        stellar_xdr::curr::Hash::from([2; 32]).into(),
                    )
                    .to_string()
                    .parse()
                    .unwrap(),
                    destination_chain: chain_name!("ethereum"),
                    destination_address: format!("0x{:x}", H160::repeat_byte(0)).parse().unwrap(),
                    payload_hash: [4; 32],
                },
                TxEventConfirmation {
                    message_id: msg_ids[1].to_string().parse().unwrap(),
                    source_address: ScAddress::Contract(
                        stellar_xdr::curr::Hash::from([2; 32]).into(),
                    )
                    .to_string()
                    .parse()
                    .unwrap(),
                    destination_chain: chain_name!("ethereum"),
                    destination_address: format!("0x{:x}", H160::repeat_byte(1)).parse().unwrap(),
                    payload_hash: [5; 32],
                },
                TxEventConfirmation {
                    message_id: msg_ids[2].to_string().parse().unwrap(),
                    source_address: ScAddress::Contract(
                        stellar_xdr::curr::Hash::from([2; 32]).into(),
                    )
                    .to_string()
                    .parse()
                    .unwrap(),
                    destination_chain: chain_name!("ethereum"),
                    destination_address: format!("0x{:x}", H160::repeat_byte(2)).parse().unwrap(),
                    payload_hash: [6; 32],
                },
            ],
        }
    }

    fn mock_handler_client(latest_block_height: u64) -> MockHandlerTaskClient {
        let mut client = MockHandlerTaskClient::new();
        client
            .expect_latest_block_height()
            .returning(move || Ok(latest_block_height));
        client
    }

    #[test]
    fn should_not_deserialize_incorrect_message_event() {
        // incorrect event type
        let mut event: Event = into_structured_event(
            message_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut event_type, ..
            } => {
                *event_type = "incorrect".into();
            }
            _ => panic!("incorrect event type"),
        }
        let event: error_stack::Result<MessagesPollStarted, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            EventTypeMismatch(_)
        ));
    }

    #[test]
    fn stellar_verify_msg_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            message_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: MessagesPollStarted = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn should_skip_expired_message_poll() {
        let mut rpc_client = MockStellarClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client
            .expect_transaction_responses()
            .returning(|_| Err(ampd::stellar::rpc_client::Error::TxHash.into()));

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier_contract,
        );

        let (monitoring_client, _) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.as_ref().clone())
            .voting_verifier_contract(voting_verifier_contract.as_ref().clone())
            .chain(chain_name!(STELLAR))
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration + 1);

        let result = handler.handle(event.try_into().unwrap(), &mut client).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[async_test]
    async fn should_record_message_verification_vote_metric() {
        let mut rpc_client = MockStellarClient::new();
        rpc_client
            .expect_transaction_responses()
            .returning(|_| Ok(HashMap::new()));

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.as_ref().clone())
            .voting_verifier_contract(voting_verifier_contract.as_ref().clone())
            .chain(chain_name!(STELLAR))
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(99);

        let result = handler.handle(event.try_into().unwrap(), &mut client).await;
        assert!(result.is_ok());

        for _ in 0..3 {
            let msg = receiver.recv().await.unwrap();
            assert_eq!(
                msg,
                monitoring::metrics::Msg::VerificationVote {
                    vote_decision: Vote::NotFound,
                    chain_name: chain_name!(STELLAR),
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        let msg_id = HexTxHashAndEventIndex::new([1u8; 32], 100u64);
        PollStarted::VerifierSet {
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: VerifierSetConfirmation {
                message_id: msg_id.to_string().parse().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ed25519, &ed25519_test_data::signers()),
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!(STELLAR),
                source_gateway_address: ScAddress::Contract(
                    stellar_xdr::curr::Hash::from([2; 32]).into(),
                )
                .to_string()
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

    #[async_test]
    async fn should_skip_expired_verifier_set_poll() {
        let mut rpc_client = MockStellarClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client
            .expect_transaction_responses()
            .returning(|_| Err(ampd::stellar::rpc_client::Error::TxHash.into()));

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.as_ref().clone())
            .voting_verifier_contract(voting_verifier.as_ref().clone())
            .chain(chain_name!(STELLAR))
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration + 1);

        let result = handler.handle(event.try_into().unwrap(), &mut client).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[async_test]
    async fn should_record_verifier_set_verification_vote_metric() {
        let mut rpc_client = MockStellarClient::new();
        rpc_client
            .expect_transaction_responses()
            .returning(|_| Ok(HashMap::new()));

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.as_ref().clone())
            .voting_verifier_contract(voting_verifier_contract.as_ref().clone())
            .chain(chain_name!(STELLAR))
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(99);

        let result = handler.handle(event.try_into().unwrap(), &mut client).await;
        assert!(result.is_ok());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            monitoring::metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: chain_name!(STELLAR),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn stellar_verify_verifier_set_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: VerifierSetPollStarted = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }
}

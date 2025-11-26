use std::collections::{HashMap, HashSet};

use ampd::handlers::sui_verify_msg::Message;
use ampd::handlers::sui_verify_verifier_set::VerifierSetConfirmation;
use ampd::monitoring;
use ampd::sui::json_rpc::SuiClient;
use ampd::sui::verifier::{verify_message, verify_verifier_set};
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

    fn tx_hash(&self) -> TransactionDigest {
        self.message_id().tx_digest.into()
    }

    fn message_id(&self) -> &Base58TxDigestAndEventIndex {
        match self {
            PollEventData::Message(message) => &message.message_id,
            PollEventData::VerifierSet(verifier_set) => &verifier_set.message_id,
        }
    }

    fn verify(
        &self,
        source_gateway_address: &SuiAddress,
        tx_receipt: &SuiTransactionBlockResponse,
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
        let attributes = HashMap::from([(
            "source_chain".to_string(),
            serde_json::Value::String(self.chain.to_string()),
        )]);

        SubscriptionParams::new(
            vec![
                AbciEventTypeFilter {
                    event_type: MessagesPollStarted::event_type(),
                    contract: self.voting_verifier_contract.clone(),
                    attributes: attributes.clone(),
                },
                AbciEventTypeFilter {
                    event_type: VerifierSetPollStarted::event_type(),
                    contract: self.voting_verifier_contract.clone(),
                    attributes,
                },
            ],
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ampd::handlers::test_utils::{into_structured_event, participants};
    use ampd::monitoring::{metrics, test_utils};
    use ampd::sui::json_rpc::MockSuiClient;
    use ampd::types::TMAddress;
    use ampd_sdk::grpc::client::test_utils::MockHandlerTaskClient;
    use axelar_wasm_std::chain_name;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use error_stack::Report;
    use ethers_core::types::H160;
    use ethers_providers::ProviderError;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use sui_types::base_types::{SuiAddress, SUI_ADDRESS_LENGTH};
    use tokio::test as async_test;
    use voting_verifier::events::{
        PollMetadata, PollStarted, TxEventConfirmation, VerifierSetConfirmation,
    };

    use super::{
        Base58TxDigestAndEventIndex, Error, Event, EventHandler, Handler, PollStartedEvent, Vote,
    };

    const PREFIX: &str = "axelar";

    fn message_poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let msg_id = Base58TxDigestAndEventIndex::new([1; 32], 0u64);
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!("sui"),
                source_gateway_address: SuiAddress::from_bytes([3; SUI_ADDRESS_LENGTH])
                    .unwrap()
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
            messages: vec![TxEventConfirmation {
                message_id: msg_id.to_string().parse().unwrap(),
                source_address: SuiAddress::from_bytes([4; SUI_ADDRESS_LENGTH])
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                destination_chain: chain_name!("ethereum"),
                destination_address: format!("0x{:x}", H160::repeat_byte(3)).parse().unwrap(),
                payload_hash: [2; 32],
            }],
        }
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        let msg_id = Base58TxDigestAndEventIndex::new([5; 32], 0u64);
        PollStarted::VerifierSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!("sui"),
                source_gateway_address: SuiAddress::from_bytes([3; SUI_ADDRESS_LENGTH])
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                confirmation_height: 1,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            verifier_set: VerifierSetConfirmation {
                message_id: msg_id.to_string().parse().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
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
    fn sui_verify_msg_should_deserialize_correct_event() {
        let event: PollStartedEvent = into_structured_event(
            message_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into()
        .unwrap();

        goldie::assert_debug!(event);
    }

    #[test]
    fn sui_verify_verifier_set_should_deserialize_correct_event() {
        let event: PollStartedEvent = into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into()
        .unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn failed_to_get_finalized_tx_blocks() {
        let mut rpc_client = MockSuiClient::new();
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| {
                Err(Report::from(ProviderError::CustomError(
                    "failed to get tx blocks".to_string(),
                )))
            });

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event: Event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("sui"))
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        let res = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap_err();

        assert!(matches!(res.current_context(), Error::FinalizedTxs));
    }

    // Should not handle event if it is not emitted from voting verifier
    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let mut rpc_client = MockSuiClient::new();
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| Ok(HashMap::new()));

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            message_poll_started_event(participants(5, None), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("sui"))
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        let res = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();

        assert_eq!(res, vec![]);
    }

    #[async_test]
    async fn should_vote_correctly() {
        let mut rpc_client = MockSuiClient::new();
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| Ok(HashMap::new()));

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("sui"))
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        let res = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();

        assert_eq!(res.len(), 1);
        assert!(MsgExecuteContract::from_any(res.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_record_message_verification_vote_metric() {
        let mut rpc_client = MockSuiClient::new();
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| Ok(HashMap::new()));

        let sui_chain_name = chain_name!("sui");
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(sui_chain_name.clone())
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        let _ = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();

        let metric = receiver.recv().await.unwrap();

        assert_eq!(
            metric,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: sui_chain_name,
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_record_verifier_set_verification_vote_metric() {
        let mut rpc_client = MockSuiClient::new();
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| Ok(HashMap::new()));

        let sui_chain_name = chain_name!("sui");
        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            verifier_set_poll_started_event(vec![verifier.clone()].into_iter().collect(), 100),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(sui_chain_name.clone())
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        let _ = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();

        let metric = receiver.recv().await.unwrap();

        assert_eq!(
            metric,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: sui_chain_name,
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_skip_expired_message_poll() {
        let mut rpc_client = MockSuiClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| {
                Err(Report::from(ProviderError::CustomError(
                    "failed to get tx blocks".to_string(),
                )))
            });

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("sui"))
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        // poll is not expired yet, should hit rpc error
        assert!(handler
            .handle(event.clone().try_into().unwrap(), &mut client)
            .await
            .is_err());

        let mut client = mock_handler_client(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(
            handler
                .handle(event.try_into().unwrap(), &mut client)
                .await
                .unwrap(),
            vec![]
        );
    }

    #[async_test]
    async fn should_skip_expired_verifier_set_poll() {
        let mut rpc_client = MockSuiClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client
            .expect_finalized_transaction_blocks()
            .returning(|_| {
                Err(Report::from(ProviderError::CustomError(
                    "failed to get tx blocks".to_string(),
                )))
            });

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;

        let event: Event = into_structured_event(
            verifier_set_poll_started_event(
                vec![verifier.clone()].into_iter().collect(),
                expiration,
            ),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!("sui"))
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(expiration - 1);

        // poll is not expired yet, should hit rpc error
        assert!(handler
            .handle(event.clone().try_into().unwrap(), &mut client)
            .await
            .is_err());

        let mut client = mock_handler_client(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(
            handler
                .handle(event.try_into().unwrap(), &mut client)
                .await
                .unwrap(),
            vec![]
        );
    }
}

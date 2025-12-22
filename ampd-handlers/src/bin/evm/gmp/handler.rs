use std::collections::HashMap;

use ampd::monitoring;
use ampd::types::EVMAddress;
use ampd_handlers::evm::finalizer;
use ampd_handlers::evm::finalizer::Finalization;
use ampd_handlers::evm::json_rpc::EthereumClient;
use ampd_handlers::evm::types::{Message, VerifierSetConfirmation};
use ampd_handlers::evm::verifier::{verify_message, verify_verifier_set};
use ampd_handlers::voting::{self, Error, PollEventData as _, VotingHandler};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::{AccountId, Any};
use error_stack::{Report, ResultExt};
use ethers_core::types::{TransactionReceipt, U64};
use events::{try_from, AbciEventTypeFilter, Event, EventType};
use futures::future::join_all;
use serde::Deserialize;
use typed_builder::TypedBuilder;

pub type Result<T> = error_stack::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-messages_poll_started")]
pub struct MessagesPollStarted {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: EVMAddress,
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
    source_gateway_address: EVMAddress,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<AccountId>,
}

#[derive(Clone, Debug, Deserialize)]
pub enum PollEventData {
    Message(Message),
    VerifierSet(VerifierSetConfirmation),
}

impl voting::PollEventData for PollEventData {
    type Digest = axelar_wasm_std::hash::Hash;
    type MessageId = HexTxHashAndEventIndex;
    type ChainAddress = EVMAddress;
    type Receipt = TransactionReceipt;
    type ContextData = ();

    fn tx_hash(&self) -> axelar_wasm_std::hash::Hash {
        self.message_id().tx_hash
    }

    fn message_id(&self) -> &HexTxHashAndEventIndex {
        match self {
            PollEventData::Message(message) => &message.message_id,
            PollEventData::VerifierSet(verifier_set) => &verifier_set.message_id,
        }
    }

    fn verify(
        &self,
        source_gateway_address: &EVMAddress,
        tx_receipt: &TransactionReceipt,
        _: &Self::ContextData,
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

impl From<PollStartedEvent> for voting::PollStartedEvent<PollEventData, EVMAddress> {
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
                confirmation_height: Some(message_event.confirmation_height),
                participants: message_event.participants,
            },
            PollStartedEvent::VerifierSet(verifier_set_event) => voting::PollStartedEvent {
                poll_data: vec![PollEventData::VerifierSet(verifier_set_event.verifier_set)],
                poll_id: verifier_set_event.poll_id,
                source_chain: verifier_set_event.source_chain,
                source_gateway_address: verifier_set_event.source_gateway_address,
                expires_at: verifier_set_event.expires_at,
                confirmation_height: Some(verifier_set_event.confirmation_height),
                participants: verifier_set_event.participants,
            },
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
impl<C> VotingHandler for Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    type Digest = axelar_wasm_std::hash::Hash;
    type Receipt = TransactionReceipt;
    type ChainAddress = EVMAddress;
    type EventData = PollEventData;
    type ContextData = ();

    fn chain(&self) -> &ChainName {
        &self.chain
    }
    fn context_data(&self) -> &Self::ContextData {
        &()
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
        confirmation_height: Option<u64>,
    ) -> Result<HashMap<Self::Digest, Self::Receipt>> {
        let confirmation_height = confirmation_height.expect("confirmation height is required");

        let tx_hashes = poll_data.iter().map(|data| data.tx_hash().into());

        let latest_finalized_block_height =
            finalizer::pick(&self.finalizer_type, &self.rpc_client, confirmation_height)
                .latest_finalized_block_height()
                .await
                .change_context(Error::FinalizedTxs)
                .attach_printable("failed to get chain's latest finalized block height")?;

        let rcp_client = &self.rpc_client;
        Ok(join_all(
            tx_hashes
                .into_iter()
                .map(|tx_hash| rcp_client.transaction_receipt(tx_hash)),
        )
        .await
        .into_iter()
        .filter_map(std::result::Result::unwrap_or_default)
        .filter_map(|tx_receipt| {
            if tx_receipt
                .block_number
                .unwrap_or(U64::MAX)
                .le(&latest_finalized_block_height)
            {
                Some((tx_receipt.transaction_hash.into(), tx_receipt))
            } else {
                None
            }
        })
        .collect())
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
    use std::convert::TryInto;

    use ampd::monitoring;
    use ampd::types::{Hash, TMAddress};
    use ampd_handlers::evm::finalizer::Finalization;
    use ampd_handlers::evm::json_rpc::MockEthereumClient;
    use ampd_handlers::test_utils::{into_structured_event, participants};
    use ampd_sdk::event::event_handler::EventHandler;
    use ampd_sdk::grpc::client::test_utils::MockHandlerTaskClient;
    use axelar_wasm_std::chain_name;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use error_stack::{Report, Result};
    use ethers_core::types::{Block, H160, H256, U64};
    use ethers_providers::ProviderError;
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use tokio::test as async_test;
    use voting_verifier::events::{
        PollMetadata, PollStarted, TxEventConfirmation, VerifierSetConfirmation,
    };

    use super::{Handler, MessagesPollStarted, VerifierSetPollStarted};

    const PREFIX: &str = "axelar";
    const ETHEREUM: &str = "ethereum";

    fn message_poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let msg_ids = [
            HexTxHashAndEventIndex::new(H256::repeat_byte(1), 0u64),
            HexTxHashAndEventIndex::new(H256::repeat_byte(2), 1u64),
            HexTxHashAndEventIndex::new(H256::repeat_byte(3), 10u64),
        ];
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!(ETHEREUM),
                source_gateway_address: "0x4f4495243837681061c4743b74eedf548d5686a5"
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
                    source_address: format!("0x{:x}", H160::repeat_byte(1)).parse().unwrap(),
                    destination_chain: chain_name!(ETHEREUM),
                    destination_address: format!("0x{:x}", H160::repeat_byte(2)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(4).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    message_id: msg_ids[1].to_string().parse().unwrap(),
                    source_address: format!("0x{:x}", H160::repeat_byte(3)).parse().unwrap(),
                    destination_chain: chain_name!(ETHEREUM),
                    destination_address: format!("0x{:x}", H160::repeat_byte(4)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(5).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    message_id: msg_ids[2].to_string().parse().unwrap(),
                    source_address: format!("0x{:x}", H160::repeat_byte(5)).parse().unwrap(),
                    destination_chain: chain_name!(ETHEREUM),
                    destination_address: format!("0x{:x}", H160::repeat_byte(6)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(6).to_fixed_bytes(),
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
        let event: Result<MessagesPollStarted, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            EventTypeMismatch(_)
        ));

        // invalid field
        let mut event: Event = into_structured_event(
            message_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut attributes, ..
            } => {
                attributes.insert("source_gateway_address".into(), "invalid".into());
            }
            _ => panic!("incorrect event type"),
        }

        let event: Result<MessagesPollStarted, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            DeserializationFailed(_, _)
        ));
    }

    #[test]
    fn evm_verify_msg_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            message_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: MessagesPollStarted = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn should_skip_expired_message_poll() {
        let mut rpc_client = MockEthereumClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client.expect_finalized_block().returning(|| {
            Err(Report::from(ProviderError::CustomError(
                "failed to get finalized block".to_string(),
            )))
        });

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier_contract,
        );

        let (monitoring_client, _) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier_contract.into())
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
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
    async fn should_record_message_verification_vote_metric() {
        let mut rpc_client = MockEthereumClient::new();
        let mut block = Block::<Hash>::default();
        let block_number: U64 = 10.into();
        block.number = Some(block_number);

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(block.clone()));

        rpc_client
            .expect_transaction_receipt()
            .returning(|_| Ok(None));

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            message_poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier_contract,
        );
        let (monitoring_client, mut receiver) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier_contract.into())
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(0);

        assert!(handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .is_ok());

        for _ in 0..3 {
            let metrics = receiver.recv().await.unwrap();

            assert_eq!(
                metrics,
                monitoring::metrics::Msg::VerificationVote {
                    vote_decision: Vote::NotFound,
                    chain_name: chain_name!(ETHEREUM),
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn evm_verify_verifier_set_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: VerifierSetPollStarted = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn should_skip_expired_verifier_set_poll() {
        let mut rpc_client = MockEthereumClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client.expect_finalized_block().returning(|| {
            Err(Report::from(ProviderError::CustomError(
                "failed to get finalized block".to_string(),
            )))
        });

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier,
        );

        let (monitoring_client, _) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier.into())
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
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
    async fn should_record_verifier_set_verification_vote_metric() {
        let mut rpc_client = MockEthereumClient::new();

        let mut block = Block::<Hash>::default();
        let block_number: U64 = 10.into();
        block.number = Some(block_number);

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(block.clone()));

        rpc_client
            .expect_transaction_receipt()
            .returning(|_| Ok(None));

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            verifier_set_poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier_contract,
        );
        let (monitoring_client, mut receiver) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(verifier.into())
            .voting_verifier_contract(voting_verifier_contract.into())
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(0);

        assert!(handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .is_ok());

        let metrics = receiver.recv().await.unwrap();

        assert_eq!(
            metrics,
            monitoring::metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: chain_name!(ETHEREUM),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        let msg_id = HexTxHashAndEventIndex::new(H256::repeat_byte(1), 100u64);
        PollStarted::VerifierSet {
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: VerifierSetConfirmation {
                message_id: msg_id.to_string().parse().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!(ETHEREUM),
                source_gateway_address: "0x4f4495243837681061c4743b74eedf548d5686a5"
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
}

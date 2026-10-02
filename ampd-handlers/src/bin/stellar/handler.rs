use std::collections::HashMap;

use ampd::monitoring;
use ampd_handlers::stellar::rpc_client::{StellarClient, TxResponse};
use ampd_handlers::stellar::types::{Message, VerifierSetConfirmation};
use ampd_handlers::stellar::verifier::{verify_message, verify_verifier_set};
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
    type ContextData = ();

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
                confirmation_height: None,
                participants: message_event.participants,
            },
            PollStartedEvent::VerifierSet(verifier_set_event) => voting::PollStartedEvent {
                poll_data: vec![PollEventData::VerifierSet(verifier_set_event.verifier_set)],
                poll_id: verifier_set_event.poll_id,
                source_chain: verifier_set_event.source_chain,
                source_gateway_address: verifier_set_event.source_gateway_address,
                expires_at: verifier_set_event.expires_at,
                confirmation_height: None,
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
            .filter_map(|(tx_hash_str, tx_response)| {
                let tx_hash = HexBinary::from_hex(&tx_hash_str)
                    .ok()?
                    .as_slice()
                    .try_into()
                    .ok()?;
                Some((tx_hash, tx_response))
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
    use std::collections::{HashMap, HashSet};
    use std::convert::TryInto;
    use std::str::FromStr;

    use ampd::monitoring;
    use ampd::types::TMAddress;
    use ampd_handlers::stellar::rpc_client::{MockStellarClient, TxResponse};
    use ampd_handlers::test_utils::{into_structured_event, participants};
    use ampd_sdk::event::event_handler::EventHandler;
    use ampd_sdk::grpc::client::test_utils::MockHandlerTaskClient;
    use axelar_wasm_std::chain_name;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use ethers_core::types::H160;
    use events::Error::EventTypeMismatch;
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ed25519_test_data};
    use stellar_rpc_client::{GetTransactionEvents, GetTransactionResponse};
    use stellar_xdr::curr::{
        ContractEvent, ContractEventBody, ContractEventType, ContractEventV0, ExtensionPoint, Hash,
        InnerTransactionResultPair, ScAddress, ScBytes, ScString, ScSymbol, ScVal, StringM,
        TransactionMeta, TransactionResult, TransactionResultResult,
    };
    use tokio::test as async_test;
    use voting_verifier::events::{
        PollMetadata, PollStarted, TxEventConfirmation, VerifierSetConfirmation,
    };

    use super::{Handler, MessagesPollStarted, VerifierSetPollStarted};

    const PREFIX: &str = "axelar";
    const STELLAR: &str = "stellar";
    const INNER_TX_HASH: [u8; 32] = [1; 32];
    const OUTER_TX_HASH: [u8; 32] = [2; 32];
    const MESSAGE_EVENT_INDEX: u64 = 4;

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
        rpc_client
            .expect_transaction_responses()
            .returning(|_| Err(ampd_handlers::stellar::rpc_client::Error::TxHash.into()));

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

    #[async_test]
    async fn fee_bump_poll_votes_only_for_inner_hash() {
        let outer_then_inner = votes_for_fee_bump_hashes([OUTER_TX_HASH, INNER_TX_HASH]).await;
        assert_eq!(
            outer_then_inner,
            vec![Vote::NotFound, Vote::SucceededOnChain]
        );

        let inner_then_outer = votes_for_fee_bump_hashes([INNER_TX_HASH, OUTER_TX_HASH]).await;
        assert_eq!(
            inner_then_outer,
            vec![Vote::SucceededOnChain, Vote::NotFound]
        );
    }

    #[async_test]
    async fn repeated_fee_bump_ids_have_the_same_vote_without_handler_replay_state() {
        // Repeated IDs use one lookup. On-chain poll/message state handles replay prevention;
        // the handler itself must not change its answer based on lookup order or repetition.
        let repeated_inner = votes_for_fee_bump_hashes([INNER_TX_HASH, INNER_TX_HASH]).await;
        assert_eq!(
            repeated_inner,
            vec![Vote::SucceededOnChain, Vote::SucceededOnChain]
        );

        let repeated_outer = votes_for_fee_bump_hashes([OUTER_TX_HASH, OUTER_TX_HASH]).await;
        assert_eq!(repeated_outer, vec![Vote::NotFound, Vote::NotFound]);
    }

    async fn votes_for_fee_bump_hashes(hashes: [[u8; 32]; 2]) -> Vec<Vote> {
        let verifier = TMAddress::random(PREFIX);
        let poll = message_poll_for_hashes(hashes, &verifier);
        let contract_event = matching_call_contract_event(&poll);
        let response = successful_fee_bump_response(INNER_TX_HASH, contract_event);
        let rpc_client = mock_rpc_returning_same_transaction(hashes, response);

        run_message_poll(poll, verifier, rpc_client).await
    }

    fn message_poll_for_hashes(hashes: [[u8; 32]; 2], verifier: &TMAddress) -> PollStarted {
        let mut poll = message_poll_started_event(participants(5, Some(verifier.clone())), 100);
        let PollStarted::Messages { messages, .. } = &mut poll else {
            unreachable!();
        };
        let template = messages[0].clone();
        *messages = hashes
            .into_iter()
            .map(|hash| TxEventConfirmation {
                message_id: HexTxHashAndEventIndex::new(hash, MESSAGE_EVENT_INDEX)
                    .to_string()
                    .parse()
                    .unwrap(),
                ..template.clone()
            })
            .collect();
        poll
    }

    fn matching_call_contract_event(poll: &PollStarted) -> ContractEvent {
        let PollStarted::Messages { metadata, messages } = poll else {
            panic!("expected message poll");
        };
        let ScAddress::Contract(gateway_contract) =
            ScAddress::from_str(metadata.source_gateway_address.as_str()).unwrap()
        else {
            panic!("expected contract gateway address");
        };
        let message = &messages[0];

        ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: Some(gateway_contract),
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: vec![
                    ScVal::Symbol(ScSymbol(StringM::from_str("contract_called").unwrap())),
                    ScVal::Address(ScAddress::from_str(message.source_address.as_str()).unwrap()),
                    ScVal::String(ScString(
                        StringM::from_str(message.destination_chain.as_ref()).unwrap(),
                    )),
                    ScVal::String(ScString(
                        StringM::from_str(message.destination_address.as_str()).unwrap(),
                    )),
                    ScVal::Bytes(ScBytes(message.payload_hash.to_vec().try_into().unwrap())),
                ]
                .try_into()
                .unwrap(),
                data: ScVal::Void,
            }),
        }
    }

    fn successful_fee_bump_response(
        inner_hash: [u8; 32],
        contract_event: ContractEvent,
    ) -> GetTransactionResponse {
        GetTransactionResponse {
            status: "SUCCESS".into(),
            envelope: None,
            result: Some(TransactionResult {
                result: TransactionResultResult::TxFeeBumpInnerSuccess(
                    InnerTransactionResultPair {
                        transaction_hash: Hash::from(inner_hash),
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }),
            result_meta: Some(TransactionMeta::V4(Default::default())),
            events: GetTransactionEvents {
                // Include a matching event at MESSAGE_EVENT_INDEX (4).
                contract_events: vec![vec![contract_event; 5]],
                diagnostic_events: vec![],
                transaction_events: vec![],
            },
        }
    }

    fn mock_rpc_returning_same_transaction(
        hashes: [[u8; 32]; 2],
        response: GetTransactionResponse,
    ) -> MockStellarClient {
        let expected_hashes = hashes
            .into_iter()
            .map(|hash| Hash::from(hash).to_string())
            .collect::<HashSet<_>>();
        let mut rpc_client = MockStellarClient::new();
        rpc_client
            .expect_transaction_responses()
            .times(1)
            .withf(move |hashes| hashes == &expected_hashes)
            .returning(move |hashes| {
                // Mock only the RPC response. Exercise the real converter for each alias,
                // dropping parse errors exactly as Client::validate_tx_response does.
                Ok(hashes
                    .into_iter()
                    .filter_map(|hash| {
                        TxResponse::try_from((Hash::from_str(&hash).unwrap(), response.clone()))
                            .ok()
                            .map(|receipt| (receipt.tx_hash(), receipt))
                    })
                    .collect())
            });
        rpc_client
    }

    async fn run_message_poll(
        poll: PollStarted,
        verifier: TMAddress,
        rpc_client: MockStellarClient,
    ) -> Vec<Vote> {
        let voting_verifier_contract = TMAddress::random(PREFIX);
        let event = into_structured_event(poll, &voting_verifier_contract);
        let (monitoring_client, _) = monitoring::test_utils::monitoring_client();
        let handler = Handler::builder()
            .verifier(verifier.as_ref().clone())
            .voting_verifier_contract(voting_verifier_contract.as_ref().clone())
            .chain(chain_name!(STELLAR))
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();
        let mut client = mock_handler_client(99);
        let result = handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .unwrap();
        decode_votes(&result)
    }

    fn decode_votes(messages: &[cosmrs::Any]) -> Vec<Vote> {
        assert_eq!(messages.len(), 1);
        let vote_msg = MsgExecuteContract::from_any(&messages[0]).unwrap();
        let execute_msg: voting_verifier::msg::ExecuteMsg =
            serde_json::from_slice(&vote_msg.msg).unwrap();
        let voting_verifier::msg::ExecuteMsg::Vote { votes, .. } = execute_msg else {
            panic!("expected vote message");
        };
        votes
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        let msg_id = HexTxHashAndEventIndex::new([1u8; 32], 100u64);

        PollStarted::VerifierSet {
            #[allow(deprecated)]
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
        rpc_client
            .expect_transaction_responses()
            .returning(|_| Err(ampd_handlers::stellar::rpc_client::Error::TxHash.into()));

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

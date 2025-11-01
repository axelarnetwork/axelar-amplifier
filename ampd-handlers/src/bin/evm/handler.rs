use std::collections::HashMap;

use ampd::evm::finalizer;
use ampd::evm::finalizer::Finalization;
use ampd::evm::json_rpc::EthereumClient;
use ampd::evm::verifier::{verify_message, verify_verifier_set};
use ampd::handlers::evm_verify_msg::Message;
use ampd::handlers::evm_verify_verifier_set::VerifierSetConfirmation;
use ampd::monitoring;
use ampd::monitoring::metrics;
use ampd::types::{EVMAddress, Hash};
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
use error_stack::{Report, ResultExt};
use ethers_core::types::{TransactionReceipt, U64};
use events::{try_from, AbciEventTypeFilter, Event, EventType};
use futures::future::join_all;
use serde::Deserialize;
use tracing::{debug, info, info_span};
use typed_builder::TypedBuilder;
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::Error;

pub type Result<T> = error_stack::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
pub struct PollStartedEvent {
    poll_data: Vec<PollEventData>,
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: EVMAddress,
    expires_at: u64,
    confirmation_height: u64,
    participants: Vec<AccountId>,
}

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

impl PollEventData {
    pub fn tx_hash(&self) -> axelar_wasm_std::hash::Hash {
        self.message_id().tx_hash
    }

    pub fn message_id(&self) -> &HexTxHashAndEventIndex {
        match self {
            PollEventData::Message(message) => &message.message_id,
            PollEventData::VerifierSet(verifier_set) => &verifier_set.message_id,
        }
    }

    pub fn verify(
        &self,
        source_gateway_address: &EVMAddress,
        tx_receipt: &TransactionReceipt,
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

impl TryFrom<Event> for PollStartedEvent {
    type Error = Report<events::Error>;

    fn try_from(event: Event) -> std::result::Result<Self, Self::Error> {
        if let Ok(event) = MessagesPollStarted::try_from(event.clone()) {
            let MessagesPollStarted {
                poll_id,
                source_chain,
                source_gateway_address,
                messages,
                expires_at,
                confirmation_height,
                participants,
            } = event;
            Ok(PollStartedEvent {
                poll_data: messages.into_iter().map(PollEventData::Message).collect(),
                poll_id,
                source_chain,
                source_gateway_address,
                expires_at,
                confirmation_height,
                participants,
            })
        } else if let Ok(event) = VerifierSetPollStarted::try_from(event.clone()) {
            let VerifierSetPollStarted {
                poll_id,
                source_chain,
                source_gateway_address,
                expires_at,
                confirmation_height,
                participants,
                verifier_set,
            } = event;
            Ok(PollStartedEvent {
                poll_data: vec![PollEventData::VerifierSet(verifier_set)],
                poll_id,
                source_chain,
                source_gateway_address,
                expires_at,
                confirmation_height,
                participants,
            })
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
        let PollStartedEvent {
            poll_id,
            source_chain,
            source_gateway_address,
            expires_at,
            confirmation_height,
            participants,
            poll_data,
        } = event;

        if self
            .should_skip_handling(
                client,
                source_chain.clone(),
                participants,
                expires_at,
                poll_id,
            )
            .await?
        {
            return Ok(vec![]);
        }

        let tx_hashes = poll_data.iter().map(|data| data.tx_hash().into());

        let finalized_tx_receipts = self
            .finalized_tx_receipts(tx_hashes, confirmation_height)
            .await?;

        let poll_id_str: String = poll_id.to_string();
        let source_chain_str: String = source_chain.to_string();

        let votes = info_span!(
            "verify events from an EVM chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            message_ids = poll_data
                .iter()
                .map(|data| data.message_id().to_string())
                .collect::<Vec<String>>()
                .as_value(),
        )
        .in_scope(|| {
            info!("ready to verify events in poll",);

            let votes: Vec<_> = poll_data
                .iter()
                .map(|data| {
                    finalized_tx_receipts
                        .get(&data.tx_hash().into())
                        .map_or(Vote::NotFound, |tx_receipt| {
                            data.verify(&source_gateway_address, tx_receipt)
                        })
                })
                .inspect(|vote| {
                    self.monitoring_client.metrics().record_metric(
                        metrics::Msg::VerificationVote {
                            vote_decision: vote.clone(),
                            chain_name: self.chain.clone(),
                        },
                    );
                })
                .collect();
            info!(
                votes = votes.as_value(),
                "ready to vote for messages in poll"
            );

            votes
        });

        Ok(vec![self
            .vote_msg(poll_id, votes)
            .into_any()
            .expect("vote msg should serialize")])
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

impl<C> Handler<C>
where
    C: EthereumClient,
{
    pub async fn should_skip_handling<HC>(
        &self,
        client: &mut HC,
        source_chain: ChainName,
        participants: Vec<AccountId>,
        expires_at: u64,
        poll_id: PollId,
    ) -> Result<bool>
    where
        HC: EventHandlerClient + Send + 'static,
    {
        // Skip if the source chain is not the same as the handler chain
        if source_chain != self.chain {
            debug!(
                event_chain = source_chain.to_string(),
                handler_chain = self.chain.to_string(),
                "chain mismatch, skipping event"
            );
            return Ok(true);
        }

        // Skip if the verifier is not a participant
        if !participants.contains(&self.verifier) {
            debug!(
                verifier = self.verifier.to_string(),
                "verifier not in participants, skipping event"
            );
            return Ok(true);
        }

        // Skip if the poll has expired
        let latest_block_height = client
            .latest_block_height()
            .await
            .change_context(Error::EventHandling)?;
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(true);
        }

        Ok(false)
    }

    /// Retrieves finalized transaction receipts for one or more transactions
    ///
    /// Returns a HashMap where keys are transaction hashes and values are receipts.
    /// Only receipts that are finalized (at or before the latest finalized block) are included.
    pub async fn finalized_tx_receipts<T>(
        &self,
        tx_hashes: T,
        confirmation_height: u64,
    ) -> Result<HashMap<Hash, TransactionReceipt>>
    where
        C: EthereumClient + Send + Sync,
        T: IntoIterator<Item = Hash>,
    {
        let latest_finalized_block_height =
            finalizer::pick(&self.finalizer_type, &self.rpc_client, confirmation_height)
                .latest_finalized_block_height()
                .await
                .change_context(Error::Finalizer)?;

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
                Some((tx_receipt.transaction_hash, tx_receipt))
            } else {
                None
            }
        })
        .collect())
    }

    /// Creates a vote message for one or more votes
    ///
    /// Pass a single vote as `vec![vote]` or multiple votes as a vector.
    pub fn vote_msg<V>(&self, poll_id: PollId, votes: V) -> MsgExecuteContract
    where
        V: Into<Vec<Vote>>,
    {
        MsgExecuteContract {
            sender: self.verifier.clone(),
            contract: self.voting_verifier_contract.clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote {
                poll_id,
                votes: votes.into(),
            })
            .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use ampd::evm::finalizer::Finalization;
    use ampd::evm::json_rpc::MockEthereumClient;
    use ampd::handlers::test_utils::{into_structured_event, participants};
    use ampd::monitoring;
    use ampd::types::{Hash, TMAddress};
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

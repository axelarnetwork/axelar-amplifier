use std::collections::HashMap;
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use ethers_core::types::{Transaction, TransactionReceipt, H256, U64};
use event_verifier_api::evm::EvmEvent;
use event_verifier_api::{EventData, EventToVerify};
use events::Error::EventTypeMismatch;
use events::{try_from, EventType};
use futures::future::join_all;
use router_api::ChainName;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::event_sub::event_filter::{EventFilter, EventFilters};
use crate::evm::finalizer;
use crate::evm::finalizer::Finalization;
use crate::evm::json_rpc::EthereumClient;
use crate::evm::verifier::verify_events;
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::monitoring;
use crate::monitoring::metrics;
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
#[try_from("wasm-events_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    confirmation_height: u64,
    expires_at: u64,
    events: Vec<EventToVerify>,
    participants: Vec<TMAddress>,
}

#[derive(Debug)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    chain: ChainName,
    finalizer_type: Finalization,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl<C> Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        chain: ChainName,
        finalizer_type: Finalization,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            chain,
            finalizer_type,
            rpc_client,
            latest_block_height,
            monitoring_client,
        }
    }

    async fn finalized_tx_receipts(
        &self,
        events_data: &[Option<EvmEvent>],
        confirmation_height: u64,
    ) -> Result<HashMap<Hash, (TransactionReceipt, Option<Transaction>)>> {
        let latest_finalized_block_height =
            finalizer::pick(&self.finalizer_type, &self.rpc_client, confirmation_height)
                .latest_finalized_block_height()
                .await
                .change_context(Error::Finalizer)?;

        let tx_hashes_with_details_needed = events_data.iter().filter_map(|e| e.as_ref()).fold(
            HashMap::new(),
            |mut acc, event_data| {
                let tx_hash = H256::from_slice(event_data.transaction_hash.as_slice());
                let needs_details = event_data.transaction_details.is_some();

                acc.entry(tx_hash)
                    .and_modify(|existing| *existing |= needs_details)
                    .or_insert(needs_details);
                acc
            },
        );

        // we need to fetch both tx receipts and possibly full transactions. Create the futures for each first, but don't await them yet,
        // so they can be executed in parallel
        let tx_receipts_fut = join_all(
            tx_hashes_with_details_needed
                .keys()
                .map(|tx_hash| self.rpc_client.transaction_receipt(*tx_hash)),
        );

        let full_transactions_fut = join_all(
            tx_hashes_with_details_needed
                .iter()
                .filter(|(_, needs_transaction)| **needs_transaction)
                .map(|(tx_hash, _)| self.rpc_client.transaction_by_hash(*tx_hash)),
        );

        // await both futures now
        let tx_receipts = tx_receipts_fut
            .await
            .into_iter()
            .filter_map(std::result::Result::unwrap_or_default);
        let full_transactions: HashMap<H256, Transaction> = full_transactions_fut
            .await
            .into_iter()
            .filter_map(std::result::Result::unwrap_or_default)
            .map(|tx| (tx.hash, tx))
            .collect();

        Ok(tx_receipts
            .filter_map(|tx_receipt| {
                if tx_receipt
                    .block_number
                    .unwrap_or(U64::MAX)
                    .le(&latest_finalized_block_height)
                {
                    let tx = full_transactions.get(&tx_receipt.transaction_hash).cloned();
                    Some((tx_receipt.transaction_hash, (tx_receipt, tx)))
                } else {
                    None
                }
            })
            .collect())
    }

    fn vote_msg(&self, poll_id: PollId, votes: Vec<Vote>) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.as_ref().clone(),
            contract: self.voting_verifier_contract.as_ref().clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
                .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            events: events_to_verify,
            expires_at,
            confirmation_height,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(DeserializeEvent)?,
        };

        if self.chain != source_chain {
            return Ok(vec![]);
        }

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        // Deserialize event data; only keep EVM events
        let events_data: Vec<Option<EvmEvent>> = events_to_verify
            .iter()
            .map(|event_to_verify| {
                serde_json::from_str::<EventData>(&event_to_verify.event_data)
                    .ok()
                    .map(|data| match data {
                        EventData::Evm(evm_event) => evm_event,
                    })
            })
            .collect();

        let finalized_tx_receipts = self
            .finalized_tx_receipts(&events_data, confirmation_height)
            .await?;

        let poll_id_str: String = poll_id.into();
        let source_chain_str: String = source_chain.into();

        let votes = info_span!(
            "verify events from an EVM chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            event_count = events_to_verify.len(),
        )
        .in_scope(|| {
            info!("ready to verify events in poll",);

            let votes: Vec<_> = events_data
                .iter()
                .map(|event_data| {
                    // TODO: might be useful to add a different vote type for events that did not deserialize correctly, i.e. Malformed
                    event_data.as_ref().map_or(Vote::NotFound, |event_data| {
                        let tx_hash: Hash = event_data.transaction_hash.to_array().into();

                        finalized_tx_receipts
                            .get(&tx_hash)
                            .map_or(Vote::NotFound, |(tx_receipt, tx)| {
                                verify_events(tx_receipt, tx.as_ref(), event_data)
                            })
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

            info!(votes = votes.as_value(), "ready to vote for events in poll");

            votes
        });

        Ok(vec![self
            .vote_msg(poll_id, votes)
            .into_any()
            .expect("vote msg should serialize")])
    }

    fn event_filters(&self) -> EventFilters {
        EventFilters::new(
            vec![EventFilter::EventTypeAndContract(
                PollStartedEvent::event_type(),
                self.voting_verifier_contract.clone(),
            )],
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use axelar_wasm_std::fixed_size;
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std::{self, Event as CosmEvent, Uint256};
    use error_stack::{Report, Result};
    use ethers_core::types::{
        Block, Bytes, Log as EthLog, Transaction, TransactionReceipt, H160, H256, U256, U64,
    };
    use ethers_providers::ProviderError;
    use event_verifier_api::evm::{Event as ApiEvent, EvmEvent as ApiEvmEvent, TransactionDetails};
    use event_verifier_api::{EventData, EventToVerify};
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use router_api::chain_name;
    use tokio::sync::watch;
    use tokio::test as async_test;

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::evm::finalizer::Finalization;
    use crate::evm::json_rpc::MockEthereumClient;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::monitoring::{metrics, test_utils};
    use crate::types::TMAddress;
    use crate::PREFIX;

    const ETHEREUM: &str = "ethereum";

    // ---------- test helpers ----------
    fn make_finalized_block(height: u64) -> Block<crate::types::Hash> {
        Block::<crate::types::Hash> {
            number: Some(height.into()),
            ..Default::default()
        }
    }

    fn make_log(address: H160, topic0: H256, data: Bytes) -> EthLog {
        EthLog {
            address,
            topics: vec![topic0],
            data,
            ..Default::default()
        }
    }

    fn make_receipt(tx_hash: H256, logs: Vec<EthLog>) -> TransactionReceipt {
        TransactionReceipt {
            transaction_hash: tx_hash,
            status: Some(1u64.into()),
            block_number: Some(5u64.into()),
            logs,
            ..Default::default()
        }
    }

    fn make_tx(hash: H256, from: H160, to: H160, value: U256, input: Bytes) -> Transaction {
        Transaction {
            hash,
            from,
            to: Some(to),
            value,
            input,
            ..Default::default()
        }
    }

    fn make_details(from: H160, to: H160, value: Uint256, calldata: Vec<u8>) -> TransactionDetails {
        TransactionDetails {
            calldata: cosmwasm_std::HexBinary::from(calldata),
            from: fixed_size::HexBinary::<20>::try_from(from.as_bytes()).unwrap(),
            to: Some(fixed_size::HexBinary::<20>::try_from(to.as_bytes()).unwrap()),
            value,
        }
    }

    fn make_api_event_only(
        tx_hash: H256,
        contract: H160,
        topic0: H256,
        data: Bytes,
        event_index: u64,
    ) -> ApiEvmEvent {
        ApiEvmEvent {
            transaction_hash: fixed_size::HexBinary::<32>::try_from(*tx_hash.as_fixed_bytes())
                .unwrap(),
            transaction_details: None,
            events: vec![ApiEvent {
                contract_address: fixed_size::HexBinary::<20>::try_from(contract.as_bytes())
                    .unwrap(),
                event_index,
                topics: vec![
                    fixed_size::HexBinary::<32>::try_from(*topic0.as_fixed_bytes()).unwrap(),
                ],
                data: cosmwasm_std::HexBinary::from(data.to_vec()),
            }],
        }
    }

    fn make_api_event_with_details(
        tx_hash: H256,
        contract: H160,
        topic0: H256,
        data: Bytes,
        event_index: u64,
        details: TransactionDetails,
    ) -> ApiEvmEvent {
        ApiEvmEvent {
            transaction_hash: fixed_size::HexBinary::<32>::try_from(*tx_hash.as_fixed_bytes())
                .unwrap(),
            transaction_details: Some(details),
            events: vec![ApiEvent {
                contract_address: fixed_size::HexBinary::<20>::try_from(contract.as_bytes())
                    .unwrap(),
                event_index,
                topics: vec![
                    fixed_size::HexBinary::<32>::try_from(*topic0.as_fixed_bytes()).unwrap(),
                ],
                data: cosmwasm_std::HexBinary::from(data.to_vec()),
            }],
        }
    }

    fn events_json_from(evm_events: Vec<ApiEvmEvent>) -> String {
        let items: Vec<EventToVerify> = evm_events
            .into_iter()
            .map(|ev| EventToVerify {
                source_chain: chain_name!(ETHEREUM),
                event_data: serde_json::to_string(&EventData::Evm(ev)).unwrap(),
            })
            .collect();
        serde_json::to_string(&items).unwrap()
    }

    fn sample_events_json() -> String {
        // build three minimal EVM events
        let mk_evm = |byte: u8| -> ApiEvmEvent {
            let tx_hash = fixed_size::HexBinary::<32>::try_from([byte; 32]).unwrap();
            let topics = vec![fixed_size::HexBinary::<32>::try_from([1u8; 32]).unwrap()];
            let data = cosmwasm_std::HexBinary::from(vec![1, 2, 3, 4]);
            let ev = ApiEvent {
                contract_address: fixed_size::HexBinary::<20>::try_from([byte; 20]).unwrap(),
                event_index: 0,
                topics,
                data,
            };
            ApiEvmEvent {
                transaction_hash: tx_hash,
                transaction_details: None,
                events: vec![ev],
            }
        };

        let items = vec![
            EventToVerify {
                source_chain: chain_name!(ETHEREUM),
                event_data: serde_json::to_string(&EventData::Evm(mk_evm(1))).unwrap(),
            },
            EventToVerify {
                source_chain: chain_name!(ETHEREUM),
                event_data: serde_json::to_string(&EventData::Evm(mk_evm(2))).unwrap(),
            },
            EventToVerify {
                source_chain: chain_name!(ETHEREUM),
                event_data: serde_json::to_string(&EventData::Evm(mk_evm(3))).unwrap(),
            },
        ];

        serde_json::to_string(&items).unwrap()
    }

    fn poll_started_event_with_raw_events_json(
        participants: Vec<TMAddress>,
        expires_at: u64,
        events_json: String,
    ) -> CosmEvent {
        let participants_as_addr: Vec<cosmwasm_std::Addr> = participants
            .into_iter()
            .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
            .collect();

        CosmEvent::new("events_poll_started")
            .add_attribute(
                "poll_id",
                serde_json::to_string(&axelar_wasm_std::voting::PollId::from(100u64)).unwrap(),
            )
            .add_attribute("source_chain", chain_name!(ETHEREUM).to_string())
            .add_attribute("confirmation_height", 15u64.to_string())
            .add_attribute("expires_at", expires_at.to_string())
            .add_attribute(
                "participants",
                serde_json::to_string(&participants_as_addr).unwrap(),
            )
            .add_attribute("events", events_json)
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> CosmEvent {
        poll_started_event_with_raw_events_json(participants, expires_at, sample_events_json())
    }

    #[test]
    fn should_not_deserialize_incorrect_event() {
        // incorrect event type
        let mut event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
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
        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            EventTypeMismatch(_)
        ));

        // invalid field
        let mut event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut attributes, ..
            } => {
                attributes.insert("poll_id".into(), "invalid".into());
            }
            _ => panic!("incorrect event type"),
        }

        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            DeserializationFailed(_, _)
        ));
    }

    #[test]
    fn evm_verify_event_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: PollStartedEvent = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn should_skip_expired_poll() {
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
            poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier_contract,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(
            verifier,
            voting_verifier_contract,
            chain_name!(ETHEREUM),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            rx,
            monitoring_client,
        );

        // poll is not expired yet, should hit rpc error
        assert!(handler.handle(&event).await.is_err());

        let _ = tx.send(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_record_verification_vote_metric() {
        let mut rpc_client = MockEthereumClient::new();
        let mut block = Block::<crate::types::Hash>::default();
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
            poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier_contract,
        );
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            verifier,
            voting_verifier_contract,
            chain_name!(ETHEREUM),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());

        for _ in 0..3 {
            let metrics = receiver.recv().await.unwrap();

            assert_eq!(
                metrics,
                metrics::Msg::VerificationVote {
                    vote_decision: Vote::NotFound,
                    chain_name: chain_name!(ETHEREUM),
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_vote_not_found_on_malformed_event_data() {
        let mut rpc_client = MockEthereumClient::new();
        let mut block = Block::<crate::types::Hash>::default();
        let block_number: U64 = 10.into();
        block.number = Some(block_number);

        // mock finalized block so finalizer works
        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(block.clone()));

        // also mock transaction_receipt to return Some with finalized block to ensure that,
        // even if called, it wouldn't cause NotFound by itself
        let dummy_receipt = TransactionReceipt {
            transaction_hash: H256::repeat_byte(0x01),
            status: Some(1u64.into()),
            block_number: Some(5u64.into()),
            logs: vec![],
            ..Default::default()
        };
        rpc_client
            .expect_transaction_receipt()
            .returning(move |_| Ok(Some(dummy_receipt.clone())));

        // events array with one entry whose event_data is a malformed JSON string
        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);

        let malformed_events = serde_json::to_string(&vec![serde_json::json!({
            "source_chain": chain_name!(ETHEREUM),
            "event_data": "{ this is not valid json",
        })])
        .unwrap();

        let event: Event = into_structured_event(
            poll_started_event_with_raw_events_json(
                participants(1, Some(verifier.clone())),
                100,
                malformed_events,
            ),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            verifier,
            voting_verifier_contract,
            chain_name!(ETHEREUM),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());

        // Expect a single NotFound vote to be recorded
        let metrics = receiver.recv().await.unwrap();
        assert_eq!(
            metrics,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: chain_name!(ETHEREUM),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_vote_succeeded_with_matching_event_log() {
        let mut rpc_client = MockEthereumClient::new();

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(make_finalized_block(10)));

        let tx_hash: H256 = H256::repeat_byte(0x42);
        let contract_addr: H160 = H160::from([0x11u8; 20]);
        let topic0: H256 = H256::repeat_byte(0xAA);
        let data_bytes = Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]);

        let receipt = make_receipt(
            tx_hash,
            vec![make_log(contract_addr, topic0, data_bytes.clone())],
        );
        rpc_client
            .expect_transaction_receipt()
            .returning(move |_| Ok(Some(receipt.clone())));

        let evm_event = make_api_event_only(tx_hash, contract_addr, topic0, data_bytes.clone(), 0);
        let events_json = events_json_from(vec![evm_event]);

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            poll_started_event_with_raw_events_json(
                participants(1, Some(verifier.clone())),
                100,
                events_json,
            ),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            verifier,
            voting_verifier_contract,
            chain_name!(ETHEREUM),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());

        // Expect a single SucceededOnChain vote to be recorded
        let metrics = receiver.recv().await.unwrap();
        assert_eq!(
            metrics,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::SucceededOnChain,
                chain_name: chain_name!(ETHEREUM),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_vote_succeeded_with_matching_transaction_details() {
        let mut rpc_client = MockEthereumClient::new();

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(make_finalized_block(10)));

        let tx_hash: H256 = H256::repeat_byte(0x21);
        let from: H160 = H160::from([0x22u8; 20]);
        let to: H160 = H160::from([0x23u8; 20]);
        let value_u256: Uint256 = Uint256::from(12345u128);
        let calldata_bytes = vec![0xde, 0xad, 0xbe, 0xef];

        let contract_addr: H160 = H160::from([0x33u8; 20]);
        let topic0: H256 = H256::repeat_byte(0xCC);
        let data_bytes = Bytes::from(calldata_bytes.clone());
        let receipt = make_receipt(
            tx_hash,
            vec![make_log(contract_addr, topic0, data_bytes.clone())],
        );
        rpc_client
            .expect_transaction_receipt()
            .returning(move |_| Ok(Some(receipt.clone())));

        let tx = make_tx(
            tx_hash,
            from,
            to,
            U256::from_big_endian(&value_u256.to_be_bytes()),
            Bytes::from(calldata_bytes.clone()),
        );
        rpc_client
            .expect_transaction_by_hash()
            .returning(move |_| Ok(Some(tx.clone())));

        let details = make_details(from, to, value_u256, calldata_bytes.clone());
        let evm_event = make_api_event_with_details(
            tx_hash,
            contract_addr,
            topic0,
            data_bytes.clone(),
            0,
            details,
        );
        let events_json = events_json_from(vec![evm_event]);

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            poll_started_event_with_raw_events_json(
                participants(1, Some(verifier.clone())),
                100,
                events_json,
            ),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let handler = super::Handler::new(
            verifier,
            voting_verifier_contract,
            chain_name!(ETHEREUM),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());
        let metrics = receiver.recv().await.unwrap();
        assert_eq!(
            metrics,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::SucceededOnChain,
                chain_name: chain_name!(ETHEREUM)
            }
        );
        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_vote_not_found_with_mismatched_transaction_details() {
        let mut rpc_client = MockEthereumClient::new();

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(make_finalized_block(10)));

        let tx_hash: H256 = H256::repeat_byte(0x31);
        let from: H160 = H160::from([0x41u8; 20]);
        let to: H160 = H160::from([0x42u8; 20]);
        let value_u256: Uint256 = Uint256::from(222u128);
        let calldata_bytes = vec![0xaa, 0xbb, 0xcc];

        let contract_addr: H160 = H160::from([0x55u8; 20]);
        let topic0: H256 = H256::repeat_byte(0xDD);
        let data_bytes = Bytes::from(calldata_bytes.clone());
        let receipt = make_receipt(
            tx_hash,
            vec![make_log(contract_addr, topic0, data_bytes.clone())],
        );
        rpc_client
            .expect_transaction_receipt()
            .returning(move |_| Ok(Some(receipt.clone())));

        let tx = make_tx(
            tx_hash,
            from,
            to,
            U256::from(1u64),
            Bytes::from(calldata_bytes.clone()),
        );
        rpc_client
            .expect_transaction_by_hash()
            .returning(move |_| Ok(Some(tx.clone())));

        let details = make_details(from, to, value_u256, calldata_bytes.clone());
        let evm_event = make_api_event_with_details(
            tx_hash,
            contract_addr,
            topic0,
            data_bytes.clone(),
            0,
            details,
        );
        let events_json = events_json_from(vec![evm_event]);

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            poll_started_event_with_raw_events_json(
                participants(1, Some(verifier.clone())),
                100,
                events_json,
            ),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let handler = super::Handler::new(
            verifier,
            voting_verifier_contract,
            chain_name!(ETHEREUM),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());
        let metrics = receiver.recv().await.unwrap();
        assert_eq!(
            metrics,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: chain_name!(ETHEREUM)
            }
        );
        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_vote_not_found_when_event_logs_do_not_match() {
        let mut rpc_client = MockEthereumClient::new();

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(make_finalized_block(10)));

        let tx_hash: H256 = H256::repeat_byte(0x77);
        let contract_addr: H160 = H160::from([0x88u8; 20]);
        let topic0_actual: H256 = H256::repeat_byte(0x11);
        let data_bytes = Bytes::from_static(&[0x01, 0x02, 0x03]);
        let receipt = make_receipt(
            tx_hash,
            vec![make_log(contract_addr, topic0_actual, data_bytes.clone())],
        );
        rpc_client
            .expect_transaction_receipt()
            .returning(move |_| Ok(Some(receipt.clone())));

        let wrong_topic: H256 = H256::repeat_byte(0x22);
        let evm_event =
            make_api_event_only(tx_hash, contract_addr, wrong_topic, data_bytes.clone(), 0);
        let events_json = events_json_from(vec![evm_event]);

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            poll_started_event_with_raw_events_json(
                participants(1, Some(verifier.clone())),
                100,
                events_json,
            ),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let handler = super::Handler::new(
            verifier,
            voting_verifier_contract,
            chain_name!(ETHEREUM),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());
        let metrics = receiver.recv().await.unwrap();
        assert_eq!(
            metrics,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: chain_name!(ETHEREUM)
            }
        );
        assert!(receiver.try_recv().is_err());
    }
}

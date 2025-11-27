use std::collections::HashMap;
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
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
use tracing::{debug, info, info_span, warn};
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

/// Fetches finalized transaction receipts and optionally full transactions for the given events
pub async fn fetch_finalized_tx_receipts<C: EthereumClient + Send + Sync>(
    rpc_client: &C,
    finalizer_type: &Finalization,
    events_data: &[Option<EvmEvent>],
    confirmation_height: u64,
) -> Result<HashMap<Hash, (TransactionReceipt, Option<Transaction>)>> {
    let latest_finalized_block_height =
        finalizer::pick(finalizer_type, rpc_client, confirmation_height)
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
            .map(|tx_hash| rpc_client.transaction_receipt(*tx_hash)),
    );

    let full_transactions_fut = join_all(
        tx_hashes_with_details_needed
            .iter()
            .filter(|(_, needs_transaction)| **needs_transaction)
            .map(|(tx_hash, _)| rpc_client.transaction_by_hash(*tx_hash)),
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

/// Checks if a poll should be skipped based on chain, participants, and expiration
pub fn should_skip_poll<T>(
    handler_chain: &ChainName,
    source_chain: &ChainName,
    verifier: &T,
    participants: &[T],
    latest_block_height: u64,
    expires_at: u64,
    poll_id: &axelar_wasm_std::voting::PollId,
) -> bool
where
    T: PartialEq + ToString,
{
    // Skip if the source chain is not the same as the handler chain
    if handler_chain != source_chain {
        debug!(
            handler_chain = handler_chain.to_string(),
            source_chain = source_chain.to_string(),
            "chain mismatch, skipping event"
        );
        return true;
    }

    // Skip if the verifier is not a participant
    if !participants.contains(verifier) {
        debug!(
            verifier = verifier.to_string(),
            "verifier not in participants, skipping event"
        );
        return true;
    }

    // Skip if the poll has expired
    if latest_block_height >= expires_at {
        info!(poll_id = poll_id.to_string(), "skipping expired poll");
        return true;
    }

    false
}

/// Deserializes event data from EventToVerify into EvmEvent
pub fn deserialize_event_data(events_to_verify: &[EventToVerify]) -> Vec<Option<EvmEvent>> {
    events_to_verify
        .iter()
        .map(|event_to_verify| {
            let event_data = serde_json::from_str::<EventData>(&event_to_verify.event_data)
                .ok()
                .map(|data| match data {
                    EventData::Evm(evm_event) => evm_event,
                });

            if event_data.is_none() {
                warn!(
                    "event data did not deserialize correctly. event: {:?}",
                    event_to_verify
                );
            }

            event_data
        })
        .collect()
}

/// Creates a vote message for a poll
pub fn create_vote_msg(
    verifier: &AccountId,
    contract: &AccountId,
    poll_id: PollId,
    votes: Vec<Vote>,
) -> MsgExecuteContract {
    MsgExecuteContract {
        sender: verifier.clone(),
        contract: contract.clone(),
        msg: serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
            .expect("vote msg should serialize"),
        funds: vec![],
    }
}

/// Verifies events against transaction receipts and records metrics
pub fn verify_and_vote_on_events(
    events_data: &[Option<EvmEvent>],
    finalized_tx_receipts: &HashMap<Hash, (TransactionReceipt, Option<Transaction>)>,
    monitoring_client: &monitoring::Client,
    chain: &ChainName,
) -> Vec<Vote> {
    events_data
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
            monitoring_client
                .metrics()
                .record_metric(metrics::Msg::VerificationVote {
                    vote_decision: vote.clone(),
                    chain_name: chain.clone(),
                });
        })
        .collect()
}

#[derive(Clone, Deserialize, Debug)]
#[try_from("wasm-events_poll_started")]
pub struct PollStartedEvent {
    pub events: Vec<EventToVerify>,
    pub poll_id: PollId,
    pub source_chain: ChainName,
    pub expires_at: u64,
    pub participants: Vec<AccountId>,
}

#[derive(Debug)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    chain: ChainName,
    confirmation_height: u64,
    finalizer_type: Finalization,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

#[derive(typed_builder::TypedBuilder)]
#[builder(build_method(into = Result<Handler<C>>))]
pub struct HandlerParams<C>
where
    C: EthereumClient,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    chain: ChainName,
    confirmation_height: Option<u64>,
    finalizer_type: Finalization,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl<C> Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    #[allow(clippy::type_complexity)]
    pub fn builder() -> HandlerParamsBuilder<C, ((), (), (), (), (), (), (), ())> {
        HandlerParams::builder()
    }
}

impl<C> From<HandlerParams<C>> for Result<Handler<C>>
where
    C: EthereumClient,
{
    fn from(params: HandlerParams<C>) -> Self {
        let confirmation_height = match params.finalizer_type {
            Finalization::ConfirmationHeight => params
                .confirmation_height
                .ok_or(Error::MissingConfirmationHeight)?,
            // This finalizer type won't actually use the confirmation height field
            Finalization::RPCFinalizedBlock => params.confirmation_height.unwrap_or(1),
        };

        Ok(Handler {
            verifier: params.verifier,
            voting_verifier_contract: params.voting_verifier_contract,
            chain: params.chain,
            confirmation_height,
            finalizer_type: params.finalizer_type,
            rpc_client: params.rpc_client,
            latest_block_height: params.latest_block_height,
            monitoring_client: params.monitoring_client,
        })
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
            events: events_to_verify,
            poll_id,
            source_chain,
            expires_at,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(DeserializeEvent)?,
        };

        let latest_block_height = *self.latest_block_height.borrow();
        if should_skip_poll(
            &self.chain,
            &source_chain,
            self.verifier.as_ref(),
            &participants,
            latest_block_height,
            expires_at,
            &poll_id,
        ) {
            return Ok(vec![]);
        }

        let events_data = deserialize_event_data(&events_to_verify);

        let finalized_tx_receipts = fetch_finalized_tx_receipts(
            &self.rpc_client,
            &self.finalizer_type,
            &events_data,
            self.confirmation_height,
        )
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
            info!("ready to verify events in poll");
            let votes = verify_and_vote_on_events(
                &events_data,
                &finalized_tx_receipts,
                &self.monitoring_client,
                &self.chain,
            );

            info!(
                votes = format!("{:?}", votes),
                "ready to vote for events in poll"
            );

            votes
        });

        Ok(vec![create_vote_msg(
            self.verifier.as_ref(),
            self.voting_verifier_contract.as_ref(),
            poll_id,
            votes,
        )
        .into_any()
        .expect("vote msg should serialize")])
    }

    fn event_filters(&self) -> EventFilters {
        EventFilters::new(
            vec![EventFilter::builder()
                .event_type(PollStartedEvent::event_type())
                .contract(self.voting_verifier_contract.clone())
                .build()],
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use axelar_wasm_std::fixed_size;
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std::{self, Uint256};
    use error_stack::{Report, Result};
    use ethers_core::types::{
        Block, Bytes, Log as EthLog, Transaction, TransactionReceipt, H160, H256, U256, U64,
    };
    use ethers_providers::ProviderError;
    use event_verifier::events::Event as EventVerifierEvent;
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
    use crate::handlers::errors::Error as HandlerError;
    use crate::handlers::test_utils::{into_structured_event, participants};
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

    fn events_from(evm_events: Vec<ApiEvmEvent>) -> Vec<EventToVerify> {
        evm_events
            .into_iter()
            .map(|ev| EventToVerify {
                source_chain: chain_name!(ETHEREUM),
                event_data: serde_json::to_string(&EventData::Evm(ev)).unwrap(),
            })
            .collect()
    }

    fn poll_started_event_with_events(
        participants: Vec<TMAddress>,
        expires_at: u64,
        events: Vec<EventToVerify>,
    ) -> EventVerifierEvent {
        let participants_as_addr: Vec<cosmwasm_std::Addr> = participants
            .into_iter()
            .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
            .collect();

        EventVerifierEvent::EventsPollStarted {
            events,
            poll_id: "100".parse().unwrap(),
            source_chain: chain_name!(ETHEREUM),
            expires_at,
            participants: participants_as_addr,
        }
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> EventVerifierEvent {
        poll_started_event_with_events(participants, expires_at, sample_events())
    }

    fn sample_events() -> Vec<EventToVerify> {
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

        vec![
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
        ]
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
                attributes.insert("poll_id".into(), "{\"invalid\": \"json\"}".into());
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

        let handler = super::Handler::builder()
            .verifier(verifier)
            .voting_verifier_contract(voting_verifier_contract)
            .chain(chain_name!(ETHEREUM))
            .confirmation_height(Some(1))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .latest_block_height(rx)
            .monitoring_client(monitoring_client)
            .build()
            .unwrap();

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

        let handler = super::Handler::builder()
            .verifier(verifier)
            .voting_verifier_contract(voting_verifier_contract)
            .chain(chain_name!(ETHEREUM))
            .confirmation_height(Some(1))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .latest_block_height(watch::channel(0).1)
            .monitoring_client(monitoring_client)
            .build()
            .unwrap();

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

        let malformed_events = vec![EventToVerify {
            source_chain: chain_name!(ETHEREUM),
            event_data: "{ this is not valid json".to_string(),
        }];

        let event: Event = into_structured_event(
            poll_started_event_with_events(
                participants(1, Some(verifier.clone())),
                100,
                malformed_events,
            ),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = super::Handler::builder()
            .verifier(verifier)
            .voting_verifier_contract(voting_verifier_contract)
            .chain(chain_name!(ETHEREUM))
            .confirmation_height(Some(1))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .latest_block_height(watch::channel(0).1)
            .monitoring_client(monitoring_client)
            .build()
            .unwrap();

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
        let events = events_from(vec![evm_event]);

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            poll_started_event_with_events(participants(1, Some(verifier.clone())), 100, events),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = super::Handler::builder()
            .verifier(verifier)
            .voting_verifier_contract(voting_verifier_contract)
            .chain(chain_name!(ETHEREUM))
            .confirmation_height(Some(1))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .latest_block_height(watch::channel(0).1)
            .monitoring_client(monitoring_client)
            .build()
            .unwrap();

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
        let events = events_from(vec![evm_event]);

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            poll_started_event_with_events(participants(1, Some(verifier.clone())), 100, events),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let handler = super::Handler::builder()
            .verifier(verifier)
            .voting_verifier_contract(voting_verifier_contract)
            .chain(chain_name!(ETHEREUM))
            .confirmation_height(Some(1))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .latest_block_height(watch::channel(0).1)
            .monitoring_client(monitoring_client)
            .build()
            .unwrap();

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
        let events = events_from(vec![evm_event]);

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            poll_started_event_with_events(participants(1, Some(verifier.clone())), 100, events),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let handler = super::Handler::builder()
            .verifier(verifier)
            .voting_verifier_contract(voting_verifier_contract)
            .chain(chain_name!(ETHEREUM))
            .confirmation_height(Some(1))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .latest_block_height(watch::channel(0).1)
            .monitoring_client(monitoring_client)
            .build()
            .unwrap();

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
        let events = events_from(vec![evm_event]);

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            poll_started_event_with_events(participants(1, Some(verifier.clone())), 100, events),
            &voting_verifier_contract,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let handler = super::Handler::builder()
            .verifier(verifier)
            .voting_verifier_contract(voting_verifier_contract)
            .chain(chain_name!(ETHEREUM))
            .confirmation_height(Some(1))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .latest_block_height(watch::channel(0).1)
            .monitoring_client(monitoring_client)
            .build()
            .unwrap();

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

    #[test]
    fn should_error_when_confirmation_height_missing_for_confirmation_height_finalizer() {
        let rpc_client = MockEthereumClient::new();
        let (monitoring_client, _) = test_utils::monitoring_client();

        let result = super::Handler::builder()
            .verifier(TMAddress::random(PREFIX))
            .voting_verifier_contract(TMAddress::random(PREFIX))
            .chain(chain_name!(ETHEREUM))
            .confirmation_height(None)
            .finalizer_type(Finalization::ConfirmationHeight)
            .rpc_client(rpc_client)
            .latest_block_height(watch::channel(0).1)
            .monitoring_client(monitoring_client)
            .build();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().current_context(),
            HandlerError::MissingConfirmationHeight
        ));
    }

    #[test]
    fn should_accept_none_confirmation_height_for_rpc_finalized_block() {
        let rpc_client = MockEthereumClient::new();
        let (monitoring_client, _) = test_utils::monitoring_client();

        let result = super::Handler::builder()
            .verifier(TMAddress::random(PREFIX))
            .voting_verifier_contract(TMAddress::random(PREFIX))
            .chain(chain_name!(ETHEREUM))
            .confirmation_height(None)
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .rpc_client(rpc_client)
            .latest_block_height(watch::channel(0).1)
            .monitoring_client(monitoring_client)
            .build();

        assert!(result.is_ok());
        assert_eq!(result.unwrap().confirmation_height, 1);
    }
}

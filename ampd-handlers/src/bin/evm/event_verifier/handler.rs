use std::collections::HashMap;

use ampd::monitoring;
use ampd::monitoring::metrics;
use ampd::types::Hash;
use ampd_handlers::evm::finalizer;
use ampd_handlers::evm::finalizer::Finalization;
use ampd_handlers::evm::json_rpc::EthereumClient;
use ampd_handlers::evm::verifier::verify_events;
use ampd_handlers::voting::Error;
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
use error_stack::ResultExt;
use ethers_core::types::{Transaction, TransactionReceipt, H256, U64};
use event_verifier_api::evm::EvmEvent;
use event_verifier_api::{EventData, EventToVerify};
use events::try_from;
use events::{AbciEventTypeFilter, EventType};
use futures::future::join_all;
use serde::Deserialize;
use tracing::{debug, warn};
use tracing::{info, info_span};
use typed_builder::TypedBuilder;
use voting_verifier::msg::ExecuteMsg;

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
            .change_context(Error::FinalizedTxs)?;

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

#[derive(Debug, TypedBuilder)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    pub verifier: AccountId,
    pub event_verifier_contract: AccountId,
    pub chain: ChainName,
    pub finalizer_type: Finalization,
    pub confirmation_height: u64,
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
            events: events_to_verify,
            poll_id,
            source_chain,
            expires_at,
            participants,
        } = event;

        let latest_block_height = client
            .latest_block_height()
            .await
            .change_context(Error::VotingEligibility)?;

        if should_skip_poll(
            &self.chain,
            &source_chain,
            &self.verifier,
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
        .await
        .change_context(Error::FinalizedTxs)?;

        let poll_id_str: String = poll_id.to_string();
        let source_chain_str: String = source_chain.to_string();

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
            &self.verifier,
            &self.event_verifier_contract,
            poll_id,
            votes,
        )
        .into_any()
        .expect("vote msg should serialize")])
    }

    fn subscription_params(&self) -> SubscriptionParams {
        SubscriptionParams::new(
            vec![AbciEventTypeFilter {
                event_type: PollStartedEvent::event_type(),
                contract: self.event_verifier_contract.clone(),
                attributes: Default::default(),
            }],
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use ampd::monitoring;
    use ampd::types::TMAddress;
    use ampd_handlers::evm::finalizer::Finalization;
    use ampd_handlers::evm::json_rpc::MockEthereumClient;
    use ampd_handlers::test_utils::{into_structured_event, participants};
    use ampd_sdk::event::event_handler::EventHandler;
    use ampd_sdk::grpc::client::test_utils::MockHandlerTaskClient;
    use axelar_wasm_std::voting::Vote;
    use axelar_wasm_std::{chain_name, fixed_size};
    use cosmrs::AccountId;
    use error_stack::{Report, Result};
    use ethers_core::types::{Block, H256, U64};
    use ethers_providers::ProviderError;
    use event_verifier::events::Event as EventVerifierEvent;
    use event_verifier_api::evm::{Event as ApiEvent, EvmEvent as ApiEvmEvent};
    use event_verifier_api::{EventData, EventToVerify};
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use tokio::test as async_test;

    use super::{Handler, PollStartedEvent};

    const PREFIX: &str = "axelar";
    const ETHEREUM: &str = "ethereum";

    fn events_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> EventVerifierEvent {
        events_poll_started_event_with_events(participants, expires_at, sample_events())
    }

    fn events_poll_started_event_with_events(
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

    fn mock_handler_client(latest_block_height: u64) -> MockHandlerTaskClient {
        let mut client = MockHandlerTaskClient::new();
        client
            .expect_latest_block_height()
            .returning(move || Ok(latest_block_height));
        client
    }

    #[test]
    fn should_not_deserialize_incorrect_event() {
        // incorrect event type
        let mut event: Event = into_structured_event(
            events_poll_started_event(participants(5, None), 100),
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
            events_poll_started_event(participants(5, None), 100),
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
            events_poll_started_event(participants(5, None), 100),
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

        let event_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            events_poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &event_verifier_contract,
        );

        let (monitoring_client, _) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(AccountId::from(verifier))
            .event_verifier_contract(AccountId::from(event_verifier_contract))
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .confirmation_height(1)
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
    async fn should_record_verification_vote_metric() {
        let mut rpc_client = MockEthereumClient::new();
        let mut block = Block::<ampd::types::Hash>::default();
        let block_number: U64 = 10.into();
        block.number = Some(block_number);

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(block.clone()));

        rpc_client
            .expect_transaction_receipt()
            .returning(|_| Ok(None));

        let event_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            events_poll_started_event(participants(5, Some(verifier.clone())), 100),
            &event_verifier_contract,
        );
        let (monitoring_client, mut receiver) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(AccountId::from(verifier))
            .event_verifier_contract(AccountId::from(event_verifier_contract))
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .confirmation_height(1)
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

    #[async_test]
    async fn should_vote_not_found_on_malformed_event_data() {
        let mut rpc_client = MockEthereumClient::new();
        let mut block = Block::<ampd::types::Hash>::default();
        let block_number: U64 = 10.into();
        block.number = Some(block_number);

        // mock finalized block so finalizer works
        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(block.clone()));

        // also mock transaction_receipt to return Some with finalized block to ensure that,
        // even if called, it wouldn't cause NotFound by itself
        let dummy_receipt = ethers_core::types::TransactionReceipt {
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
        let event_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);

        let malformed_events = vec![EventToVerify {
            source_chain: chain_name!(ETHEREUM),
            event_data: "{ this is not valid json".to_string(),
        }];

        let event: Event = into_structured_event(
            events_poll_started_event_with_events(
                participants(1, Some(verifier.clone())),
                100,
                malformed_events,
            ),
            &event_verifier_contract,
        );

        let (monitoring_client, mut receiver) = monitoring::test_utils::monitoring_client();

        let handler = Handler::builder()
            .verifier(AccountId::from(verifier))
            .event_verifier_contract(AccountId::from(event_verifier_contract))
            .chain(chain_name!(ETHEREUM))
            .finalizer_type(Finalization::RPCFinalizedBlock)
            .confirmation_height(1)
            .rpc_client(rpc_client)
            .monitoring_client(monitoring_client)
            .build();

        let mut client = mock_handler_client(0);

        assert!(handler
            .handle(event.try_into().unwrap(), &mut client)
            .await
            .is_ok());

        // Expect a single NotFound vote to be recorded
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
}

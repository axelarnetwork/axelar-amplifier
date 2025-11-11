use std::collections::HashMap;

use ampd::evm::finalizer::{self, Finalization};
use ampd::evm::json_rpc::EthereumClient;
use ampd::monitoring;
use ampd::monitoring::metrics;
use ampd::types::Hash;
use ampd_handlers::voting::Error;
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
use error_stack::{Result, ResultExt};
use ethers_core::types::{Transaction, TransactionReceipt, H256, U64};
use event_verifier_api::evm::EvmEvent;
use event_verifier_api::{EventData, EventToVerify};
use events::{try_from, AbciEventTypeFilter, EventType};
use futures::future::join_all;
use serde::Deserialize;
use tracing::{info, info_span, warn};
use typed_builder::TypedBuilder;
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use ampd::evm::verifier::verify_events;

#[derive(Clone, Debug, Deserialize)]
#[try_from("wasm-events_poll_started")]
pub struct EventsPollStarted {
    events: Vec<EventToVerify>,
    poll_id: PollId,
    source_chain: ChainName,
    expires_at: u64,
    participants: Vec<AccountId>,
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

impl<C> Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    async fn finalized_tx_receipts(
        &self,
        events_data: &[Option<EvmEvent>],
        confirmation_height: u64,
    ) -> Result<HashMap<Hash, (TransactionReceipt, Option<Transaction>)>, Error> {
        let latest_finalized_block_height =
            finalizer::pick(&self.finalizer_type, &self.rpc_client, confirmation_height)
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
                    Some((tx_receipt.transaction_hash.into(), (tx_receipt, tx)))
                } else {
                    None
                }
            })
            .collect())
    }

    fn vote_msg(&self, poll_id: PollId, votes: Vec<Vote>) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.clone(),
            contract: self.event_verifier_contract.clone(),
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
    type Event = EventsPollStarted;

    async fn handle<HC: EventHandlerClient + Send + 'static>(
        &self,
        event: EventsPollStarted,
        client: &mut HC,
    ) -> Result<Vec<Any>, Self::Err> {
        let EventsPollStarted {
            events: events_to_verify,
            poll_id,
            source_chain,
            expires_at,
            participants,
        } = event;

        if self.chain != source_chain {
            return Ok(vec![]);
        }

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = client
            .latest_block_height()
            .await
            .change_context(Error::VotingEligibility)?;
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        // Deserialize event data; only keep EVM events
        let events_data: Vec<Option<EvmEvent>> = events_to_verify
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
            .collect();

        let finalized_tx_receipts = self
            .finalized_tx_receipts(&events_data, self.confirmation_height)
            .await?;

        let poll_id_str: String = poll_id.to_string();
        let source_chain_str: String = source_chain.to_string();

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

    fn subscription_params(&self) -> SubscriptionParams {
        SubscriptionParams::new(
            vec![AbciEventTypeFilter {
                event_type: EventsPollStarted::event_type(),
                contract: self.event_verifier_contract.clone(),
            }],
            false,
        )
    }
}


mod messages_handler;
mod verifier_set_handler;

use crate::handler::messages_handler::MessagesPollStarted;
use crate::handler::verifier_set_handler::VerifierSetPollStarted;
use crate::Error;
use ampd::evm::finalizer;
use ampd::evm::finalizer::Finalization;
use ampd::evm::json_rpc::EthereumClient;
use ampd::monitoring;
use ampd::types::Hash;
use ampd_sdk::event::event_handler::{EventHandler, SubscriptionParams};
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::{AccountId, Any};
use error_stack::{Report, ResultExt};
use ethers_core::types::{TransactionReceipt, U64};
use events::{AbciEventTypeFilter, Event, EventType};
use futures::future::join_all;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::info;
use typed_builder::TypedBuilder;
use voting_verifier::msg::ExecuteMsg;

pub type Result<T> = error_stack::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
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
        match event {
            PollStartedEvent::Messages(event) => self.handle_messages(event, client).await,
            PollStartedEvent::VerifierSet(event) => self.handle_verifier_set(event, client).await,
        }
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
            return Ok(true);
        }

        // Skip if the verifier is not a participant
        if !participants.contains(&self.verifier) {
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

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use ampd::monitoring;
use ampd::monitoring::metrics;
use ampd_sdk::event::event_handler::EventHandler;
use ampd_sdk::grpc::client::EventHandlerClient;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::{AccountId, Any};
use error_stack::ResultExt;
use thiserror::Error;
use tracing::{debug, info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

pub type Result<T> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to determine voting eligibility")]
    VotingEligibility,
    #[error("failed to retrieve finalized transactions")]
    FinalizedTxs,
}

pub trait PollEventData: Clone + Debug + Send + Sync {
    type Digest;
    type MessageId: Display;
    type ChainAddress;
    type Receipt;

    fn tx_hash(&self) -> Self::Digest;
    fn message_id(&self) -> &Self::MessageId;
    fn verify(
        &self,
        source_gateway_address: &Self::ChainAddress,
        tx_receipt: &Self::Receipt,
    ) -> Vote;
}

#[derive(Clone, Debug)]
pub struct PollStartedEvent<P, A>
where
    P: PollEventData,
    A: Clone + Debug + Send + Sync,
{
    pub poll_data: Vec<P>,
    pub poll_id: PollId,
    pub source_chain: ChainName,
    pub source_gateway_address: A,
    pub expires_at: u64,
    pub confirmation_height: u64,
    pub participants: Vec<AccountId>,
}

#[async_trait]
pub trait VotingHandler: EventHandler {
    type Digest: Eq + Hash;
    type Receipt;
    type ChainAddress: Clone + Debug + Send + Sync;
    type EventData: PollEventData<
        Digest = Self::Digest,
        Receipt = Self::Receipt,
        ChainAddress = Self::ChainAddress,
    >;

    fn chain(&self) -> &ChainName;
    fn verifier(&self) -> &AccountId;
    fn voting_verifier_contract(&self) -> &AccountId;
    fn monitoring_client(&self) -> &monitoring::Client;

    /// Retrieves finalized transaction receipts for one or more transactions
    ///
    /// Returns a HashMap where keys are transaction digests specific to the chain and values are receipts.
    /// Only receipts that are finalized (at or before the latest finalized block) are included.
    async fn finalized_txs(
        &self,
        poll_data: &[Self::EventData],
        confirmation_height: Option<u64>,
    ) -> Result<HashMap<Self::Digest, Self::Receipt>>;

    async fn should_skip_voting<HC>(
        &self,
        client: &mut HC,
        source_chain: &ChainName,
        participants: Vec<AccountId>,
        expires_at: u64,
        poll_id: &PollId,
    ) -> Result<bool>
    where
        HC: EventHandlerClient + Send + 'static,
    {
        // Skip if the source chain is not the same as the handler chain
        if source_chain != self.chain() {
            debug!(
                event_chain = source_chain.to_string(),
                handler_chain = self.chain().to_string(),
                "chain mismatch, skipping event"
            );
            return Ok(true);
        }

        // Skip if the verifier is not a participant
        if !participants.contains(self.verifier()) {
            debug!(
                verifier = self.verifier().to_string(),
                "verifier not in participants, skipping event"
            );
            return Ok(true);
        }

        // Skip if the poll has expired
        let latest_block_height = client
            .latest_block_height()
            .await
            .change_context(Error::VotingEligibility)
            .attach_printable("failed to get amplifier's latest block height")?;
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(true);
        }

        Ok(false)
    }

    /// Creates a vote message for one or more votes
    ///
    /// Pass a single vote as `vec![vote]` or multiple votes as a vector.
    fn vote_msg<V>(&self, poll_id: PollId, votes: V) -> MsgExecuteContract
    where
        V: Into<Vec<Vote>>,
    {
        MsgExecuteContract {
            sender: self.verifier().to_owned(),
            contract: self.voting_verifier_contract().to_owned(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote {
                poll_id,
                votes: votes.into(),
            })
            .expect("vote msg should serialize"),
            funds: vec![],
        }
    }

    async fn handle<HC>(
        &self,
        event: PollStartedEvent<Self::EventData, Self::ChainAddress>,
        client: &mut HC,
    ) -> Result<Vec<Any>>
    where
        HC: EventHandlerClient + Send + 'static,
    {
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
            .should_skip_voting(client, &source_chain, participants, expires_at, &poll_id)
            .await?
        {
            return Ok(vec![]);
        }

        let finalized_tx_receipts = self
            .finalized_txs(&poll_data, Some(confirmation_height))
            .await?;

        let poll_id_str: String = poll_id.to_string();
        let source_chain_str: String = source_chain.to_string();

        let votes = info_span!(
            "verify poll events",
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
                        .get(&data.tx_hash())
                        .map_or(Vote::NotFound, |tx_receipt| {
                            data.verify(&source_gateway_address, tx_receipt)
                        })
                })
                .inspect(|vote| {
                    self.monitoring_client().metrics().record_metric(
                        metrics::Msg::VerificationVote {
                            vote_decision: vote.clone(),
                            chain_name: self.chain().to_owned(),
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
}

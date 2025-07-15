use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::str::FromStr;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::try_from;
use events::Error::EventTypeMismatch;
use futures::future::join_all;
use router_api::ChainName;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span, warn};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;
use xrpl_http_client::Transaction;
use xrpl_types::msg::XRPLMessage;
use xrpl_types::types::{xrpl_account_id_string, XRPLAccountId};

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::monitoring;
use crate::monitoring::metrics::Msg as MetricsMsg;
use crate::types::TMAddress;
use crate::xrpl::json_rpc::XRPLClient;
use crate::xrpl::verifier::verify_message;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    #[serde(with = "xrpl_account_id_string")]
    source_gateway_address: XRPLAccountId,
    expires_at: u64,
    messages: Vec<XRPLMessage>,
    participants: Vec<TMAddress>,
}

#[derive(Debug)]
pub struct Handler<C>
where
    C: XRPLClient + Send + Sync,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl<C> Handler<C>
where
    C: XRPLClient + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            rpc_client,
            latest_block_height,
            monitoring_client,
        }
    }

    async fn validated_txs<T>(&self, tx_ids: T) -> Result<HashMap<HexTxHash, Transaction>>
    where
        T: IntoIterator<Item = HexTxHash>,
    {
        Ok(join_all(
            tx_ids
                .into_iter()
                .map(|tx_id| self.rpc_client.tx(tx_id.tx_hash)),
        )
        .await
        .into_iter()
        .filter_map(std::result::Result::unwrap_or_default)
        .filter_map(|tx_res| {
            let tx_common = tx_res.tx.common();
            let tx_hash = tx_common.hash.clone()?;

            if tx_common.validated != Some(true) {
                return None;
            }
            let hex_tx_hash = HexTxHash::from_str(&format!("0x{}", tx_hash.to_lowercase())).ok()?;
            Some((hex_tx_hash, tx_res.tx))
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
    C: XRPLClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            source_gateway_address,
            messages,
            expires_at,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![]);
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let tx_ids: HashSet<_> = messages.iter().map(|message| message.tx_id()).collect();
        let validated_txs = self.validated_txs(tx_ids).await?;

        let poll_id_str: String = poll_id.into();
        let source_chain_str: String = source_chain.into();
        let message_ids = messages
            .iter()
            .map(|message| message.tx_id().tx_hash_as_hex())
            .collect::<Vec<_>>();

        let handler_chain_name = "xrpl";

        let votes = info_span!(
            "verify messages from XRPL chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            message_ids = message_ids.as_value()
        )
        .in_scope(|| {
            info!("ready to verify messages in poll",);

            let votes: Vec<_> = messages
                .iter()
                .map(|msg| {
                    let vote = validated_txs
                        .get(&msg.tx_id())
                        .map_or(Vote::NotFound, |tx| {
                            verify_message(&source_gateway_address, tx, msg)
                        });

                    record_vote_outcome(&self.monitoring_client, &vote, handler_chain_name);

                    vote
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

fn record_vote_outcome(monitoring_client: &monitoring::Client, vote: &Vote, chain_name: &str) {
    if let Err(err) = monitoring_client
        .metrics()
        .record_metric(MetricsMsg::VoteOutcome {
            vote_status: vote.clone(),
            chain_name: chain_name.to_string(),
        })
    {
        warn!(error = %err,
            chain_name = %chain_name,
            "failed to record vote outcome metrics for vote {:?}", vote);
    };
}

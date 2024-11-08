use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHash;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use cosmwasm_std::HexBinary;
use error_stack::ResultExt;
use futures::future::join_all;
use serde::Deserialize;
use axelar_wasm_std::voting::{PollId, Vote};
use tokio::sync::watch::Receiver;
use valuable::Valuable;

use events_derive::try_from;
use voting_verifier::msg::ExecuteMsg;
use events::Error::EventTypeMismatch;
use tracing::{info, info_span};
use xrpl_http_client::Transaction;
use xrpl_types::msg::XRPLMessage;
use xrpl_types::types::{TxHash, XRPLAccountId, xrpl_account_id_string};

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::types::TMAddress;
use crate::xrpl::finalizer::{self, Finalization};
use crate::xrpl::json_rpc::XRPLClient;
use crate::xrpl::verifier::verify_message;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    #[serde(with = "xrpl_account_id_string")]
    source_gateway_address: XRPLAccountId,
    confirmation_height: u32,
    expires_at: u64,
    messages: Vec<XRPLMessage>,
    participants: Vec<TMAddress>,
}

pub struct Handler<C>
where
    C: XRPLClient + Send + Sync,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    finalizer_type: Finalization,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
}

impl<C> Handler<C>
where
    C: XRPLClient + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        finalizer_type: Finalization,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            finalizer_type,
            rpc_client,
            latest_block_height,
        }
    }

    async fn validated_txs<T>(
        &self,
        tx_ids: T,
        confirmation_height: u32,
    ) -> Result<HashMap<TxHash, Transaction>>
    where
        T: IntoIterator<Item = TxHash>,
    {
        let latest_validated_ledger_index =
            finalizer::pick(&self.finalizer_type, &self.rpc_client, confirmation_height)
                .latest_validated_ledger_index()
                .await
                .change_context(Error::Finalizer)?;

        Ok(join_all(
            tx_ids
                .into_iter()
                .map(|tx_id| self.rpc_client.tx(tx_id.into())),
        )
        .await
        .into_iter()
        .filter_map(std::result::Result::unwrap_or_default)
        .filter_map(|tx_res| {
            let tx_common = tx_res.tx.common();
            let (ledger_index, tx_hash) = (tx_common.ledger_index, tx_common.hash.clone());

            if ledger_index
                .unwrap_or(u32::MAX)
                .le(&latest_validated_ledger_index)
                && tx_hash.is_some()
            {
                let tx_hash = HexBinary::from_hex(tx_hash.unwrap().as_str()).ok();
                if tx_hash.is_none() {
                    return None;
                }

                let tx_hash = TxHash::try_from(tx_hash.unwrap()).ok();
                if tx_hash.is_none() {
                    return None;
                }

                Some((tx_hash.unwrap(), tx_res.tx))
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
    C: XRPLClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_gateway_address,
            messages,
            expires_at,
            confirmation_height,
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
        let validated_txs = self
            .validated_txs(tx_ids, confirmation_height)
            .await?;

        let poll_id_str: String = poll_id.into();
        let message_ids = messages
            .iter()
            .map(|message| HexTxHash::new(message.tx_id()).to_string())
            .collect::<Vec<_>>();

        let votes = info_span!(
            "verify messages from XRPL chain",
            poll_id = poll_id_str,
            message_ids = message_ids.as_value()
        )
        .in_scope(|| {
            info!("ready to verify messages in poll",);

            let votes: Vec<_> = messages
                .iter()
                .map(|msg| {
                    validated_txs
                        .get(&msg.tx_id())
                        .map_or(Vote::NotFound, |tx| {
                            verify_message(&source_gateway_address, tx, msg)
                        })
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
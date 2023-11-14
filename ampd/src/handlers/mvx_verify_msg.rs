use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use futures::future::join_all;
use serde::Deserialize;

use axelar_wasm_std::voting::PollID;
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::types::{Hash, TMAddress};

use crate::mvx::verifier::verify_message;
use multiversx_sdk::blockchain::CommunicationProxy;
use multiversx_sdk::data::address::Address;
use multiversx_sdk::data::transaction::TransactionOnNetwork;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub tx_id: String,
    pub event_index: usize,
    pub destination_address: String,
    pub destination_chain: connection_router::state::ChainName,
    pub source_address: Address,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollID,
    source_gateway_address: Address,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

pub struct Handler<B>
where
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    blockchain: CommunicationProxy,
    broadcast_client: B,
}

impl<B> Handler<B>
where
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        blockchain: CommunicationProxy,
        broadcast_client: B,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            blockchain,
            broadcast_client,
        }
    }

    async fn transactions_info_with_results(
        &self,
        tx_hashes: HashSet<String>,
    ) -> Result<HashMap<String, TransactionOnNetwork>> {
        Ok(join_all(tx_hashes.iter().map(|tx_hash| {
            self.blockchain
                .get_transaction_info_with_results(tx_hash.as_str())
        }))
        .await
        .into_iter()
        .filter_map(|tx| {
            if !tx.is_ok() {
                return None;
            }

            let tx = tx.unwrap();

            if tx.hash.is_none() {
                return None;
            }

            Some((tx.hash.clone().unwrap(), tx))
        })
        .collect())
    }

    async fn broadcast_votes(&self, poll_id: PollID, votes: Vec<bool>) -> Result<()> {
        let msg = serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
            .expect("vote msg should serialize");
        let tx = MsgExecuteContract {
            sender: self.worker.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
            msg,
            funds: vec![],
        };

        self.broadcast_client
            .broadcast(tx)
            .await
            .change_context(Error::Broadcaster)
    }
}

#[async_trait]
impl<B> EventHandler for Handler<B>
where
    B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<()> {
        let PollStartedEvent {
            contract_address,
            poll_id,
            source_gateway_address,
            messages,
            participants,
            ..
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(());
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if self.voting_verifier != contract_address {
            return Ok(());
        }

        if !participants.contains(&self.worker) {
            return Ok(());
        }

        let tx_hashes: HashSet<_> = messages
            .iter()
            .map(|message| message.tx_id.clone())
            .collect();
        let transactions_info = self
            .transactions_info_with_results(tx_hashes)
            .await
            .change_context(Error::TxReceipts)?;

        let votes = messages
            .iter()
            .map(|msg| {
                transactions_info
                    .get(&msg.tx_id)
                    .map_or(false, |transaction| {
                        verify_message(&source_gateway_address, transaction, msg)
                    })
            })
            .collect();

        self.broadcast_votes(poll_id, votes).await

        // TODO
        // let tx_hash = "49edb289892a655a0e988b360c19326c21107f9696c6197b435667c6e8c6e1a3";
        //
        // self.blockchain.get_transaction_info_with_results(tx_hash).await

        // Ok(())
    }
}

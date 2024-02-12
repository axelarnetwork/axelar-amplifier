use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use serde::Deserialize;
use axelar_wasm_std::voting::{PollId, Vote};
use tokio::sync::watch::Receiver;

use events_derive::try_from;
use voting_verifier::msg::ExecuteMsg;
use events::{Error::EventTypeMismatch, Event};
use tracing::info;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::types::{Hash, TMAddress};
use crate::xrpl::json_rpc::XRPLClient;
use crate::xrpl::verifier::verify_message;
use crate::xrpl::types::{TransactionId, XRPLAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub tx_id: TransactionId,
    pub event_index: u64,
    pub destination_address: String,
    pub destination_chain: connection_router::state::ChainName,
    pub source_address: XRPLAddress,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollId,
    source_gateway_address: XRPLAddress,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler<C, B>
where
    C: XRPLClient,
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: C,
    broadcast_client: B,
    latest_block_height: Receiver<u64>,
}

impl<C, B> Handler<C, B>
where
    C: XRPLClient,
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: C,
        broadcast_client: B,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            rpc_client,
            broadcast_client,
            latest_block_height,
        }
    }
    async fn broadcast_votes(&self, poll_id: PollId, votes: Vec<Vote>) -> Result<()> {
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
impl<C, B> EventHandler for Handler<C, B>
where
    C: XRPLClient + Send + Sync,
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
            expires_at,
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

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(());
        }

        // Does not assume voting verifier emits unique tx ids.
        // RPC will throw an error if the input contains any duplicate, deduplicate tx ids to avoid unnecessary failures.
        let deduplicated_tx_ids: HashSet<_> = messages.iter().map(|msg| msg.tx_id.clone()).collect();

        let mut tx_responses = HashMap::new();

        for tx_id in deduplicated_tx_ids {
            match self.rpc_client.fetch_tx(&tx_id).await {
                Ok(res) => { tx_responses.insert(tx_id, res); },
                Err(e) => return Err(e.change_context(Error::TxReceipts))
            }
        }

        let votes = messages
            .iter()
            .map(|msg| {
                tx_responses
                    .get(&msg.tx_id)
                    .map_or(Vote::NotFound, |tx_response| {
                        verify_message(&source_gateway_address, &tx_response.tx, msg)
                    })
            })
            .collect();

        self.broadcast_votes(poll_id, votes).await
    }
}
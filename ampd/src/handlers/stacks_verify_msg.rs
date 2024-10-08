use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::Event;
use events_derive::try_from;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::info;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::stacks::http_client::Client;
use crate::stacks::verifier::verify_message;
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub tx_id: Hash,
    pub event_index: u32,
    pub destination_address: String,
    pub destination_chain: router_api::ChainName,
    pub source_address: String, // TODO
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_gateway_address: String, // TODO
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler {
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    http_client: Client,
    latest_block_height: Receiver<u64>,
}

impl Handler {
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        http_client: Client,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            http_client,
            latest_block_height,
        }
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
impl EventHandler for Handler {
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_gateway_address,
            messages,
            participants,
            expires_at,
            ..
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

        let tx_hashes: HashSet<_> = messages.iter().map(|message| message.tx_id).collect();
        let transactions = self
            .http_client
            .get_transactions(tx_hashes)
            .await;

        let votes: Vec<Vote> = messages
            .iter()
            .map(|msg| {
                transactions
                    .get(&msg.tx_id)
                    .map_or(Vote::NotFound, |transaction| {
                        verify_message(&source_gateway_address, transaction, msg)
                    })
            })
            .collect();

        Ok(vec![self
            .vote_msg(poll_id, votes)
            .into_any()
            .expect("vote msg should serialize")])
    }
}

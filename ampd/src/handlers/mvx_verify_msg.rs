use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use serde::Deserialize;

use axelar_wasm_std::voting::PollID;
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::types::{Hash, TMAddress};

use multiversx_sdk::blockchain::{CommunicationProxy};

type Result<T> = error_stack::Result<T, Error>;

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
}

#[async_trait]
impl<B> EventHandler for Handler<B>
    where
        B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<()> {
        // let PollStartedEvent {
        //     contract_address,
        //     poll_id,
        //     source_gateway_address,
        //     messages,
        //     participants,
        //     ..
        // } = match event.try_into() as error_stack::Result<_, _> {
        //     Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
        //         return Ok(());
        //     }
        //     event => event.change_context(Error::DeserializeEvent)?,
        // };
        //
        // if self.voting_verifier != contract_address {
        //     return Ok(());
        // }
        //
        // if !participants.contains(&self.worker) {
        //     return Ok(());
        // }

        // Does not assume voting verifier emits unique tx ids.
        // RPC will throw an error if the input contains any duplicate, deduplicate tx ids to avoid unnecessary failures.
        // let deduplicated_tx_ids: HashSet<_> = messages.iter().map(|msg| msg.tx_id).collect();
        // let transaction_blocks = self
        //     .rpc_client
        //     .finalized_transaction_blocks(deduplicated_tx_ids)
        //     .await
        //     .change_context(Error::TxReceipts)?;
        //
        // let votes = messages
        //     .iter()
        //     .map(|msg| {
        //         transaction_blocks
        //             .get(&msg.tx_id)
        //             .map_or(false, |tx_block| {
        //                 verify_message(&source_gateway_address, tx_block, msg)
        //             })
        //     })
        //     .collect();
        //
        // self.broadcast_votes(poll_id, votes).await

        // TODO
        // let tx_hash = "49edb289892a655a0e988b360c19326c21107f9696c6197b435667c6e8c6e1a3";
        //
        // self.blockchain.get_transaction_info_with_results(tx_hash).await

        Ok(())
    }
}

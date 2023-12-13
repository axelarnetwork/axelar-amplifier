use std::convert::{TryFrom, TryInto};

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use serde::ser::{Serialize, Serializer};
use serde::Deserialize;
use sui_types::base_types::{SuiAddress, TransactionDigest};
use tracing::{info, info_span};

use axelar_wasm_std::voting::PollID;
use connection_router::state::ID_SEPARATOR;
use cosmwasm_std::{ConversionOverflowError, HexBinary};
use cosmwasm_std::{Uint128, Uint256};
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::sui::json_rpc::SuiClient;
use crate::sui::verifier::verify_worker_set;
use crate::types::TMAddress;

/// Poll started event uses Uint256 for weights and threshold, while Sui gateway uses u128.
/// U128 is a wrapper to deserialize Uint256 into u128.
#[derive(Deserialize, Debug, Copy, Clone)]
#[serde(try_from = "Uint256")]
pub struct U128(u128);

impl TryFrom<Uint256> for U128 {
    type Error = ConversionOverflowError;

    fn try_from(value: Uint256) -> Result<Self, Self::Error> {
        Ok(Self(Uint128::try_from(value)?.u128()))
    }
}

impl Serialize for U128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[derive(Deserialize, Debug)]
pub struct Operators {
    pub weights_by_addresses: Vec<(HexBinary, U128)>,
    pub threshold: U128,
}

#[derive(Deserialize, Debug)]
pub struct WorkerSetConfirmation {
    pub tx_id: TransactionDigest,
    pub event_index: u64,
    pub operators: Operators,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-worker_set_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollID,
    source_gateway_address: SuiAddress,
    worker_set: WorkerSetConfirmation,
    participants: Vec<TMAddress>,
}

pub struct Handler<C, B>
where
    C: SuiClient + Send + Sync,
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: C,
    broadcast_client: B,
}

impl<C, B> Handler<C, B>
where
    C: SuiClient + Send + Sync,
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: C,
        broadcast_client: B,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            rpc_client,
            broadcast_client,
        }
    }
    async fn broadcast_votes(
        &self,
        poll_id: PollID,
        votes: Vec<bool>,
    ) -> error_stack::Result<(), Error> {
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
    C: SuiClient + Send + Sync,
    B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> error_stack::Result<(), Error> {
        let PollStartedEvent {
            contract_address,
            poll_id,
            source_gateway_address,
            worker_set,
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

        let transaction_block = self
            .rpc_client
            .finalized_transaction_block(worker_set.tx_id)
            .await
            .change_context(Error::TxReceipts)?;

        let vote = info_span!(
            "verify a new worker set for Sui",
            poll_id = poll_id.to_string(),
            id = format!(
                "0x{:x}{}{}",
                worker_set.tx_id, ID_SEPARATOR, worker_set.event_index
            )
        )
        .in_scope(|| {
            let vote = transaction_block.map_or(false, |tx_receipt| {
                verify_worker_set(&source_gateway_address, &tx_receipt, &worker_set)
            });

            info!(vote, "ready to vote for a new worker set in poll");

            vote
        });

        self.broadcast_votes(poll_id, vec![vote]).await
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use axelar_wasm_std::operators::Operators;
    use cosmwasm_std::HexBinary;
    use error_stack::Result;
    use sui_types::base_types::{SuiAddress, TransactionDigest};
    use voting_verifier::events::{PollMetadata, PollStarted, WorkerSetConfirmation};

    use super::PollStartedEvent;
    use crate::PREFIX;
    use crate::{handlers::tests::get_event, types::TMAddress};

    #[test]
    fn should_deserialize_worker_set_poll_started_event() {
        let participants = (0..5)
            .into_iter()
            .map(|_| TMAddress::random(PREFIX))
            .collect();

        let event: Result<PollStartedEvent, events::Error> = get_event(
            worker_set_poll_started_event(participants),
            &TMAddress::random(PREFIX),
        )
        .try_into();

        assert!(event.is_ok());
    }

    fn worker_set_poll_started_event(participants: Vec<TMAddress>) -> PollStarted {
        PollStarted::WorkerSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "sui".parse().unwrap(),
                source_gateway_address: SuiAddress::random_for_testing_only()
                    .to_string()
                    .parse()
                    .unwrap(),
                confirmation_height: 1,
                expires_at: 100,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            worker_set: WorkerSetConfirmation {
                tx_id: TransactionDigest::random().to_string().parse().unwrap(),
                event_index: 0,
                operators: Operators {
                    weights_by_addresses: vec![
                        (
                            HexBinary::from(SuiAddress::random_for_testing_only().to_vec()),
                            1u64.into(),
                        ),
                        (
                            HexBinary::from(SuiAddress::random_for_testing_only().to_vec()),
                            1u64.into(),
                        ),
                        (
                            HexBinary::from(SuiAddress::random_for_testing_only().to_vec()),
                            1u64.into(),
                        ),
                    ],
                    threshold: 2u64.into(),
                },
            },
        }
    }
}

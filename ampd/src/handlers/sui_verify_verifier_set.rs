use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::{tx::Msg, Any};
use cosmwasm_std::HexBinary;
use cosmwasm_std::Uint128;
use error_stack::ResultExt;
use serde::Deserialize;
use sui_types::base_types::{SuiAddress, TransactionDigest};
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;

use axelar_wasm_std::msg_id::base_58_event_index::Base58TxDigestAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::sui::json_rpc::SuiClient;
use crate::sui::verifier::verify_worker_set;
use crate::types::TMAddress;

#[derive(Deserialize, Debug)]
pub struct Operators {
    pub weights_by_addresses: Vec<(HexBinary, Uint128)>,
    pub threshold: Uint128,
}

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub tx_id: TransactionDigest,
    pub event_index: u32,
    pub operators: Operators,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_gateway_address: SuiAddress,
    verifier_set: VerifierSetConfirmation,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler<C>
where
    C: SuiClient + Send + Sync,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
}

impl<C> Handler<C>
where
    C: SuiClient + Send + Sync,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            rpc_client,
            latest_block_height,
        }
    }

    fn vote_msg(&self, poll_id: PollId, vote: Vote) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.worker.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote {
                poll_id,
                votes: vec![vote],
            })
            .expect("vote msg should serialize"),
            funds: vec![],
        }
    }
}

#[async_trait]
impl<C> EventHandler for Handler<C>
where
    C: SuiClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> error_stack::Result<Vec<Any>, Error> {
        if !event.is_from_contract(self.voting_verifier.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_gateway_address,
            verifier_set,
            participants,
            expires_at,
            ..
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![]);
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if !participants.contains(&self.worker) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let transaction_block = self
            .rpc_client
            .finalized_transaction_block(verifier_set.tx_id)
            .await
            .change_context(Error::TxReceipts)?;

        let vote = info_span!(
            "verify a new worker set for Sui",
            poll_id = poll_id.to_string(),
            id = Base58TxDigestAndEventIndex::new(verifier_set.tx_id, verifier_set.event_index)
                .to_string()
        )
        .in_scope(|| {
            let vote = transaction_block.map_or(Vote::NotFound, |tx_receipt| {
                verify_worker_set(&source_gateway_address, &tx_receipt, &verifier_set)
            });

            info!(
                vote = vote.as_value(),
                "ready to vote for a new worker set in poll"
            );

            vote
        });

        Ok(vec![self
            .vote_msg(poll_id, vote)
            .into_any()
            .expect("vote msg should serialize")])
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use cosmwasm_std::HexBinary;
    use error_stack::{Report, Result};
    use ethers::providers::ProviderError;
    use sui_types::base_types::{SuiAddress, TransactionDigest};
    use tokio::sync::watch;
    use tokio::test as async_test;

    use axelar_wasm_std::operators::Operators;
    use events::Event;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use crate::event_processor::EventHandler;
    use crate::handlers::sui_verify_verifier_set;
    use crate::sui::json_rpc::MockSuiClient;
    use crate::PREFIX;
    use crate::{handlers::tests::get_event, types::TMAddress};

    use super::PollStartedEvent;

    #[test]
    fn should_deserialize_worker_set_poll_started_event() {
        let participants = (0..5).map(|_| TMAddress::random(PREFIX)).collect();

        let event: Result<PollStartedEvent, events::Error> = get_event(
            worker_set_poll_started_event(participants, 100),
            &TMAddress::random(PREFIX),
        )
        .try_into();

        assert!(event.is_ok());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut rpc_client = MockSuiClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client
            .expect_finalized_transaction_block()
            .returning(|_| {
                Err(Report::from(ProviderError::CustomError(
                    "failed to get finalized transaction blocks".to_string(),
                )))
            });

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = get_event(
            worker_set_poll_started_event(vec![worker.clone()].into_iter().collect(), expiration),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler =
            sui_verify_verifier_set::Handler::new(worker, voting_verifier, rpc_client, rx);

        // poll is not expired yet, should hit rpc error
        assert!(handler.handle(&event).await.is_err());

        let _ = tx.send(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    fn worker_set_poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        PollStarted::VerifierSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "sui".parse().unwrap(),
                source_gateway_address: SuiAddress::random_for_testing_only()
                    .to_string()
                    .parse()
                    .unwrap(),
                confirmation_height: 1,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            verifier_set: VerifierSetConfirmation {
                tx_id: TransactionDigest::random().to_string().parse().unwrap(),
                event_index: 0,
                operators: Operators::new(
                    vec![
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
                    2u64.into(),
                    1,
                ),
            },
        }
    }
}

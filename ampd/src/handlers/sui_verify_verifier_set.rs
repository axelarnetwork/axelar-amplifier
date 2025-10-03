use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::Base58TxDigestAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::{try_from, Event, EventType};
use lazy_static::lazy_static;
use multisig::verifier_set::VerifierSet;
use router_api::{chain_name, ChainName};
use serde::Deserialize;
use sui_types::base_types::SuiAddress;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::event_sub::event_filter::{EventFilter, EventFilters};
use crate::handlers::errors::Error;
use crate::monitoring;
use crate::monitoring::metrics;
use crate::sui::json_rpc::SuiClient;
use crate::sui::verifier::verify_verifier_set;
use crate::types::TMAddress;

lazy_static! {
    static ref SUI_CHAIN_NAME: ChainName = chain_name!("sui");
}

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub message_id: Base58TxDigestAndEventIndex,
    pub verifier_set: VerifierSet,
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

#[derive(Debug)]
pub struct Handler<C>
where
    C: SuiClient + Send + Sync,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl<C> Handler<C>
where
    C: SuiClient + Send + Sync,
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

    fn vote_msg(&self, poll_id: PollId, vote: Vote) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.as_ref().clone(),
            contract: self.voting_verifier_contract.as_ref().clone(),
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
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
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

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let transaction_block = self
            .rpc_client
            .finalized_transaction_block(verifier_set.message_id.tx_digest.into())
            .await
            .change_context(Error::TxReceipts)?;

        let vote = info_span!(
            "verify a new verifier set for Sui",
            poll_id = poll_id.to_string(),
            id = verifier_set.message_id.to_string()
        )
        .in_scope(|| {
            let vote = transaction_block.map_or(Vote::NotFound, |tx_receipt| {
                verify_verifier_set(&source_gateway_address, &tx_receipt, &verifier_set)
            });

            self.monitoring_client
                .metrics()
                .record_metric(metrics::Msg::VerificationVote {
                    vote_decision: vote.clone(),
                    chain_name: SUI_CHAIN_NAME.clone(),
                });

            info!(
                vote = vote.as_value(),
                "ready to vote for a new verifier set in poll"
            );

            vote
        });

        Ok(vec![self
            .vote_msg(poll_id, vote)
            .into_any()
            .expect("vote msg should serialize")])
    }

    fn event_filters(&self) -> EventFilters {
        EventFilters::new(
            vec![EventFilter::EventTypeAndContract(
                PollStartedEvent::event_type(),
                self.voting_verifier_contract.clone(),
            )],
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use axelar_wasm_std::msg_id::Base58TxDigestAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use error_stack::Report;
    use ethers_providers::ProviderError;
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use router_api::chain_name;
    use sui_types::base_types::{SuiAddress, SUI_ADDRESS_LENGTH};
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{Event as VotingVerifierEvent, VerifierSetConfirmation};

    use super::{PollStartedEvent, SUI_CHAIN_NAME};
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::monitoring::{metrics, test_utils};
    use crate::sui::json_rpc::MockSuiClient;
    use crate::types::TMAddress;
    use crate::PREFIX;

    #[test]
    fn sui_verify_verifier_set_should_deserialize_correct_event() {
        let event: PollStartedEvent = into_structured_event(
            verifier_set_poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into()
        .unwrap();

        goldie::assert_debug!(event);
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
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            verifier_set_poll_started_event(
                vec![verifier.clone()].into_iter().collect(),
                expiration,
            ),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler =
            super::Handler::new(verifier, voting_verifier, rpc_client, rx, monitoring_client);

        // poll is not expired yet, should hit rpc error
        assert!(handler.handle(&event).await.is_err());

        let _ = tx.send(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_record_verification_vote_metric() {
        let mut rpc_client = MockSuiClient::new();
        rpc_client
            .expect_finalized_transaction_block()
            .returning(|_| Ok(None));

        let voting_verifier = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            verifier_set_poll_started_event(vec![verifier.clone()].into_iter().collect(), 100),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let handler = super::Handler::new(
            verifier,
            voting_verifier,
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: SUI_CHAIN_NAME.clone(),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> VotingVerifierEvent {
        let msg_id = Base58TxDigestAndEventIndex::new([5; 32], 0u64);
        VotingVerifierEvent::VerifierSetPollStarted {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!("sui"),
                source_gateway_address: SuiAddress::from_bytes([3; SUI_ADDRESS_LENGTH])
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                confirmation_height: 1,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                .collect(),
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: VerifierSetConfirmation {
                tx_id: msg_id.tx_digest_as_base58(),
                event_index: u32::try_from(msg_id.event_index).unwrap(),
                message_id: msg_id.to_string().parse().unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
        }
    }
}

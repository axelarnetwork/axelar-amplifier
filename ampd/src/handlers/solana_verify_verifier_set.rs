use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::{try_from, EventType};
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;
use serde::Deserialize;
use solana_transaction_status::UiTransactionStatusMeta;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::event_sub::event_filter::{EventFilter, EventFilters};
use crate::handlers::errors::Error;
use crate::monitoring;
use crate::monitoring::metrics;
use crate::solana::verifier_set_verifier::verify_verifier_set;
use crate::solana::SolanaRpcClientProxy;
use crate::types::TMAddress;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct VerifierSetConfirmation {
    pub message_id: Base58SolanaTxSignatureAndEventIndex,
    pub verifier_set: VerifierSet,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-verifier_set_poll_started")]
struct PollStartedEvent {
    verifier_set: VerifierSetConfirmation,
    poll_id: PollId,
    source_chain: ChainName,
    expires_at: u64,
    participants: Vec<TMAddress>,
}

pub struct Handler<C: SolanaRpcClientProxy> {
    chain_name: ChainName,
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    solana_gateway_domain_separator: [u8; 32],
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl<C: SolanaRpcClientProxy> Handler<C> {
    pub async fn new(
        chain_name: ChainName,
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
    ) -> Self {
        let domain_separator = rpc_client
            .domain_separator()
            .await
            .expect("cannot start handler without fetching domain separator for Solana");

        Self {
            chain_name,
            verifier,
            solana_gateway_domain_separator: domain_separator,
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

    async fn fetch_message(
        &self,
        msg: &VerifierSetConfirmation,
    ) -> Option<(solana_sdk::signature::Signature, UiTransactionStatusMeta)> {
        let signature = solana_sdk::signature::Signature::from(msg.message_id.raw_signature);
        self.rpc_client
            .tx(&signature)
            .await
            .map(|tx| (signature, tx))
    }
}

#[async_trait]
impl<C: SolanaRpcClientProxy> EventHandler for Handler<C> {
    type Err = Error;

    async fn handle(&self, event: &events::Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            expires_at,
            participants,
            verifier_set,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if source_chain != self.chain_name {
            return Ok(vec![]);
        }

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let tx_receipt = self.fetch_message(&verifier_set).await;
        let vote = info_span!(
            "verify a new verifier set for Solana",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            id = verifier_set.message_id.to_string()
        )
        .in_scope(|| {
            info!("ready to verify a new verifier set in poll");

            let vote = tx_receipt.map_or(Vote::NotFound, |(signature, tx_receipt)| {
                verify_verifier_set(
                    (&signature, &tx_receipt),
                    &verifier_set,
                    &self.solana_gateway_domain_separator,
                )
            });

            self.monitoring_client
                .metrics()
                .record_metric(metrics::Msg::VerificationVote {
                    vote_decision: vote.clone(),
                    chain_name: self.chain_name.clone(),
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
    use std::str::FromStr;

    use axelar_wasm_std::voting::Vote;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use cosmrs::AccountId;
    use cosmwasm_std;
    use events::Event;
    use multisig::key::KeyType;
    use multisig::test::common::{build_verifier_set, ecdsa_test_data};
    use router_api::chain_name;
    use solana_sdk::signature::Signature;
    use solana_transaction_status::option_serializer::OptionSerializer;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, VerifierSetConfirmation};

    use super::*;
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::into_structured_event;
    use crate::monitoring::{metrics, test_utils};
    use crate::types::TMAddress;
    use crate::PREFIX;

    const SOLANA: &str = "solana";

    struct EmptyResponseSolanaRpc;
    #[async_trait::async_trait]
    impl SolanaRpcClientProxy for EmptyResponseSolanaRpc {
        async fn tx(&self, _signature: &Signature) -> Option<UiTransactionStatusMeta> {
            None
        }

        async fn domain_separator(&self) -> Option<[u8; 32]> {
            Some([42; 32])
        }
    }

    struct ValidResponseSolanaRpc;
    #[async_trait::async_trait]
    impl SolanaRpcClientProxy for ValidResponseSolanaRpc {
        async fn tx(&self, _signature: &Signature) -> Option<UiTransactionStatusMeta> {
            Some(UiTransactionStatusMeta {
                err: None,
                status: Ok(()),
                fee: 0,
                pre_balances: vec![],
                post_balances: vec![],
                inner_instructions: OptionSerializer::None,
                log_messages: OptionSerializer::None,
                pre_token_balances: OptionSerializer::None,
                post_token_balances: OptionSerializer::None,
                rewards: OptionSerializer::None,
                loaded_addresses: OptionSerializer::None,
                return_data: OptionSerializer::None,
                compute_units_consumed: OptionSerializer::None,
            })
        }

        async fn domain_separator(&self) -> Option<[u8; 32]> {
            Some([42; 32])
        }
    }

    #[test]
    fn solana_verify_verifier_set_should_deserialize_correct_event() {
        let event: PollStartedEvent = into_structured_event(
            verifier_set_poll_started_event(participants(None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into()
        .unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn not_poll_started_event() {
        let event = into_structured_event(
            cosmwasm_std::Event::new("transfer"),
            &TMAddress::random(PREFIX),
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            chain_name!(SOLANA),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            EmptyResponseSolanaRpc,
            watch::channel(0).1,
            monitoring_client,
        )
        .await;

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = into_structured_event(
            verifier_set_poll_started_event(participants(None), 100),
            &TMAddress::random(PREFIX),
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            chain_name!(SOLANA),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            EmptyResponseSolanaRpc,
            watch::channel(0).1,
            monitoring_client,
        )
        .await;

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn verifier_is_not_a_participant() {
        let voting_verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            verifier_set_poll_started_event(participants(None), 100),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            chain_name!(SOLANA),
            TMAddress::random(PREFIX),
            voting_verifier,
            EmptyResponseSolanaRpc,
            watch::channel(0).1,
            monitoring_client,
        )
        .await;

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_skip_expired_poll() {
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

        let handler = super::Handler::new(
            chain_name!(SOLANA),
            verifier,
            voting_verifier,
            ValidResponseSolanaRpc,
            rx,
            monitoring_client,
        )
        .await;

        // poll is not expired yet, should hit proxy
        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_vote_correctly() {
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(Some(worker.clone())), 100),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            chain_name!(SOLANA),
            worker,
            voting_verifier,
            ValidResponseSolanaRpc,
            watch::channel(0).1,
            monitoring_client,
        )
        .await;

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_record_verification_vote_metric() {
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);

        let event = into_structured_event(
            verifier_set_poll_started_event(participants(Some(worker.clone())), 100),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            chain_name!(SOLANA),
            worker,
            voting_verifier,
            ValidResponseSolanaRpc,
            watch::channel(0).1,
            monitoring_client,
        )
        .await;

        let _ = handler.handle(&event).await.unwrap();

        let metrics = receiver.recv().await.unwrap();
        assert_eq!(
            metrics,
            metrics::Msg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: chain_name!(SOLANA),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    fn verifier_set_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        let signature_1 = "3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP";
        let event_idx_1 = 10_u32;
        let message_id_1 = format!("{signature_1}-{event_idx_1}");
        PollStarted::VerifierSet {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!(SOLANA),
                source_gateway_address: axelar_solana_gateway::ID.to_string().parse().unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            verifier_set: VerifierSetConfirmation {
                tx_id: signature_1
                    .parse()
                    .unwrap(),
                event_index: event_idx_1,
                message_id: message_id_1
                    .to_string()
                    .try_into()
                    .unwrap(),
                verifier_set: build_verifier_set(KeyType::Ecdsa, &ecdsa_test_data::signers()),
            },
        }
    }

    fn participants(worker: Option<TMAddress>) -> Vec<TMAddress> {
        let mut participants = vec![
            AccountId::from_str("axelar1hg8mfs0pauxmxt5n76ndnlrye235zgz877l727")
                .unwrap()
                .into(),
            AccountId::from_str("axelar19neataahn59zsgex8479u9my28e0rae8c3hd6g")
                .unwrap()
                .into(),
            AccountId::from_str("axelar1fjh9eftylh82egzvcldmv5jyfuscvehqvxr8es")
                .unwrap()
                .into(),
            AccountId::from_str("axelar1s3gutkdnlr7gn9meanysm2muhz4g7w4x63ay0q")
                .unwrap()
                .into(),
            AccountId::from_str("axelar1k4mztxaugnqwf0hfp878785z887clvq2vkt7tq")
                .unwrap()
                .into(),
        ];

        if let Some(worker) = worker {
            participants.push(worker);
        }

        participants
    }
}

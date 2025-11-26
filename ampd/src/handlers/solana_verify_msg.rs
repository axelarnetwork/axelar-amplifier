use std::collections::HashMap;
use std::convert::TryInto;
use std::str::FromStr;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::Base58SolanaTxSignatureAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::{try_from, EventType};
use router_api::ChainName;
use serde::Deserialize;
use solana_sdk::pubkey::Pubkey;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span, warn};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::event_sub::event_filter::{EventFilter, EventFilters};
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::monitoring;
use crate::monitoring::metrics;
use crate::solana::msg_verifier::verify_message;
use crate::solana::{SolanaRpcClientProxy, SolanaTransaction};
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub message_id: Base58SolanaTxSignatureAndEventIndex,
    pub destination_address: String,
    pub destination_chain: ChainName,
    #[serde(deserialize_with = "crate::solana::deserialize_pubkey")]
    pub source_address: Pubkey,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: String,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

pub struct Handler<C: SolanaRpcClientProxy> {
    chain_name: ChainName,
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
    gateway_address: Pubkey,
}

impl<C: SolanaRpcClientProxy> Handler<C> {
    pub fn new(
        chain_name: ChainName,
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
        gateway_address: &str,
    ) -> Result<Self> {
        let gateway_address = solana_sdk::pubkey::Pubkey::from_str(gateway_address)
            .change_context(Error::PublicKey)?;

        Ok(Self {
            chain_name,
            verifier,
            voting_verifier_contract,
            rpc_client,
            latest_block_height,
            monitoring_client,
            gateway_address,
        })
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

    async fn fetch_message(&self, msg: &Message) -> Option<SolanaTransaction> {
        let signature = solana_sdk::signature::Signature::from(msg.message_id.raw_signature);
        self.rpc_client.tx(&signature).await
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
            source_gateway_address,
            messages,
            expires_at,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(DeserializeEvent)?,
        };

        if source_chain != self.chain_name {
            return Ok(vec![]);
        }

        // Validate that the source gateway address matches the configured gateway address
        if source_gateway_address != self.gateway_address.to_string() {
            warn!(
                poll_id = poll_id.to_string(),
                expected_gateway = %self.gateway_address,
                actual_gateway = %source_gateway_address,
                "skipping poll due to gateway address mismatch"
            );
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

        let tx_calls = messages.iter().map(|msg| async {
            self.fetch_message(msg)
                .await
                .map(|tx| (msg.message_id.raw_signature.into(), tx))
        });
        let finalized_tx_receipts = futures::future::join_all(tx_calls)
            .await
            .into_iter()
            .flatten()
            .collect::<HashMap<solana_sdk::signature::Signature, SolanaTransaction>>();

        let votes = info_span!(
            "verify messages from Solana",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            message_ids = messages
                .iter()
                .map(|msg| msg.message_id.to_string())
                .collect::<Vec<String>>()
                .as_value(),
        )
        .in_scope(|| {
            info!("ready to verify messages in poll",);

            let votes: Vec<_> = messages
                .iter()
                .map(|msg| {
                    finalized_tx_receipts
                        .get(&msg.message_id.raw_signature.into())
                        .map_or(Vote::NotFound, |tx| {
                            verify_message(tx, msg, &self.gateway_address)
                        })
                })
                .inspect(|vote| {
                    self.monitoring_client.metrics().record_metric(
                        metrics::Msg::VerificationVote {
                            vote_decision: vote.clone(),
                            chain_name: self.chain_name.clone(),
                        },
                    );
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

    fn event_filters(&self) -> EventFilters {
        EventFilters::new(
            vec![EventFilter::builder()
                .event_type(Some(PollStartedEvent::event_type()))
                .contract(Some(self.voting_verifier_contract.clone()))
                .attributes(HashMap::new())
                .build()
                .expect("event filter should be valid")],
            true,
        )
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use axelar_wasm_std::voting::Vote;
    use cosmrs::AccountId;
    use router_api::{address, chain_name};
    use solana_sdk::signature::Signature;
    use tokio::sync::watch;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::*;
    use crate::handlers::test_utils::into_structured_event;
    use crate::monitoring::{metrics, test_utils};
    use crate::types::TMAddress;
    use crate::PREFIX;

    const SOLANA: &str = "solana";
    const ETHEREUM: &str = "ethereum";

    struct EmptyResponseSolanaRpc;
    #[async_trait::async_trait]
    impl SolanaRpcClientProxy for EmptyResponseSolanaRpc {
        async fn tx(&self, _signature: &Signature) -> Option<SolanaTransaction> {
            None
        }

        async fn domain_separator(&self, _gateway_address: &Pubkey) -> Option<[u8; 32]> {
            unimplemented!()
        }
    }

    struct ValidResponseSolanaRpc;
    #[async_trait::async_trait]
    impl SolanaRpcClientProxy for ValidResponseSolanaRpc {
        async fn tx(&self, signature: &Signature) -> Option<SolanaTransaction> {
            Some(SolanaTransaction {
                signature: *signature,
                inner_instructions: vec![],
                err: None,
                account_keys: vec![axelar_solana_gateway::ID], // Gateway program at index 0
            })
        }

        async fn domain_separator(&self, _gateway_address: &Pubkey) -> Option<[u8; 32]> {
            unimplemented!()
        }
    }

    #[test]
    fn solana_verify_msg_should_deserialize_correct_event() {
        let event: PollStartedEvent = into_structured_event(
            poll_started_event(participants(None), 100),
            &TMAddress::random(PREFIX),
        )
        .try_into()
        .unwrap();

        goldie::assert_debug!(event);
    }

    // Should not handle event if it is not a poll started event
    #[tokio::test]
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
            &axelar_solana_gateway::ID.to_string(),
        )
        .unwrap();

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if it is not emitted from voting verifier
    #[tokio::test]
    async fn contract_is_not_voting_verifier() {
        let event = into_structured_event(
            poll_started_event(participants(None), 100),
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
            &axelar_solana_gateway::ID.to_string(),
        )
        .unwrap();

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if worker is not a poll participant
    #[tokio::test]
    async fn verifier_is_not_a_participant() {
        let voting_verifier = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(None), 100),
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
            &axelar_solana_gateway::ID.to_string(),
        )
        .unwrap();

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if source gateway address doesn't match configured gateway
    #[tokio::test]
    async fn should_skip_poll_with_mismatched_gateway_address() {
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);

        // Create an event with a different gateway address
        let mut event_data = poll_started_event(participants(Some(worker.clone())), 100);
        if let PollStarted::Messages {
            ref mut metadata, ..
        } = event_data
        {
            // Use a different gateway address
            metadata.source_gateway_address = "DifferentGatewayAddress123456789".parse().unwrap();
        }

        let event = into_structured_event(event_data, &voting_verifier);

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            chain_name!(SOLANA),
            worker,
            voting_verifier,
            ValidResponseSolanaRpc,
            watch::channel(0).1,
            monitoring_client,
            &axelar_solana_gateway::ID.to_string(),
        )
        .unwrap();

        // Should return empty vec due to gateway address mismatch
        let result = handler.handle(&event).await.unwrap();
        assert_eq!(result, vec![]);
    }

    #[tokio::test]
    async fn should_vote_correctly() {
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(Some(worker.clone())), 100),
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
            &axelar_solana_gateway::ID.to_string(),
        )
        .unwrap();

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn should_record_verification_vote_metric() {
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(Some(worker.clone())), 100),
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
            &axelar_solana_gateway::ID.to_string(),
        )
        .unwrap();

        let _ = handler.handle(&event).await.unwrap();

        for _ in 0..2 {
            let msg = receiver.recv().await.unwrap();
            assert_eq!(
                msg,
                metrics::Msg::VerificationVote {
                    vote_decision: Vote::NotFound,
                    chain_name: chain_name!(SOLANA),
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn should_skip_expired_poll() {
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(Some(worker.clone())), expiration),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            chain_name!(SOLANA),
            worker,
            voting_verifier,
            ValidResponseSolanaRpc,
            rx,
            monitoring_client,
            &axelar_solana_gateway::ID.to_string(),
        )
        .unwrap();

        // poll is not expired yet, should hit proxy
        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let signature_1 = "3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP";
        let inner_ix_group_index_1 = 1_u32;
        let inner_ix_index_1 = 10_u32;
        let message_id_1 = format!("{signature_1}-{inner_ix_group_index_1}.{inner_ix_index_1}");

        let signature_2 = "41SgBTfsWbkdixDdVNESM6YmDAzEcKEubGPkaXmtTVUd2EhMaqPEy3qh5ReTtTb4Le4F16SSBFjQCxkekamNrFNT";
        let inner_ix_group_index_2 = 2_u32;
        let inner_ix_index_2 = 88_u32;
        let message_id_2 = format!("{signature_2}-{inner_ix_group_index_2}.{inner_ix_index_2}");

        let source_gateway_address = axelar_solana_gateway::ID;

        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: chain_name!(SOLANA),
                source_gateway_address: source_gateway_address.to_string().parse().unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            #[allow(deprecated)]
            messages: vec![
                TxEventConfirmation {
                    source_address: Pubkey::from_str(
                        "9Tp4XJZLQKdM82BHYfNAG6V3RWpLC7Y5mXo1UqKZFTJ3",
                    )
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                    message_id: message_id_1.parse().unwrap(),
                    destination_chain: chain_name!(ETHEREUM),
                    destination_address: address!("0x3ad1f33ef5814e7adb43ed7fb39f9b45053ecab1"),
                    payload_hash: Hash::from_slice(&[1; 32]).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    source_address: Pubkey::from_str(
                        "H1QLZVpX7B4WMNY5UqKZG3RFTJ9M82BXoLQF26TJCY5N",
                    )
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                    message_id: message_id_2.parse().unwrap(),
                    destination_chain: chain_name!(ETHEREUM),
                    destination_address: address!("0x3ad1f33ef5814e7adb43ed7fb39f9b45053ecab2"),
                    payload_hash: Hash::from_slice(&[2; 32]).to_fixed_bytes(),
                },
            ],
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

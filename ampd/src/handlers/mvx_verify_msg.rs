use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::{try_from, Event};
use lazy_static::lazy_static;
use multiversx_sdk::data::address::Address;
use router_api::{chain_name, ChainName};
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::monitoring;
use crate::monitoring::metrics::Msg as MetricsMsg;
use crate::mvx::proxy::MvxProxy;
use crate::mvx::verifier::verify_message;
use crate::types::{Hash, TMAddress};

lazy_static! {
    static ref MULTIVERSX_CHAIN_NAME: ChainName = chain_name!("multiversx");
}

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub message_id: HexTxHashAndEventIndex,
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_address: Address,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_gateway_address: Address,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

#[derive(Debug)]
pub struct Handler<P>
where
    P: MvxProxy + Send + Sync,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    blockchain: P,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl<P> Handler<P>
where
    P: MvxProxy + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        blockchain: P,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            blockchain,
            latest_block_height,
            monitoring_client,
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
impl<P> EventHandler for Handler<P>
where
    P: MvxProxy + Send + Sync,
{
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

        let tx_hashes: HashSet<Hash> = messages
            .iter()
            .map(|message| message.message_id.tx_hash.into())
            .collect();
        let transactions_info = self
            .blockchain
            .transactions_info_with_results(tx_hashes)
            .await;

        let poll_id_str: String = poll_id.into();

        let votes = info_span!(
            "verify messages for MultiversX",
            poll_id = poll_id_str,
            message_ids = messages
                .iter()
                .map(|msg| msg.message_id.to_string())
                .collect::<Vec<String>>()
                .as_value(),
        )
        .in_scope(|| {
            info!("ready to verify messages in poll",);

            let votes: Vec<Vote> = messages
                .iter()
                .map(|msg| {
                    transactions_info
                        .get(&msg.message_id.tx_hash.into())
                        .map_or(Vote::NotFound, |transaction| {
                            verify_message(&source_gateway_address, transaction, msg)
                        })
                })
                .inspect(|vote| {
                    self.monitoring_client
                        .metrics()
                        .record_metric(MetricsMsg::VerificationVote {
                            vote_decision: vote.clone(),
                            chain_name: MULTIVERSX_CHAIN_NAME.clone(),
                        });
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::TryInto;

    use axelar_wasm_std::voting::Vote;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use cosmwasm_std;
    use ethers_core::types::H160;
    use hex::ToHex;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::{PollStartedEvent, MULTIVERSX_CHAIN_NAME};
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::monitoring::metrics::Msg as MetricsMsg;
    use crate::monitoring::test_utils;
    use crate::mvx::proxy::MockMvxProxy;
    use crate::types::TMAddress;
    use crate::PREFIX;

    #[test]
    fn mvx_verify_msg_should_deserialize_correct_event() {
        let event: PollStartedEvent = into_structured_event(
            poll_started_event(participants(5, None)),
            &TMAddress::random(PREFIX),
        )
        .try_into()
        .unwrap();

        goldie::assert_debug!(&event);

        assert!(event.poll_id == 100u64.into());
        assert!(
            event.source_gateway_address.to_bech32_string().unwrap()
                == "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx"
        );

        let message = event.messages.first().unwrap();

        assert!(
            message.message_id.tx_hash.encode_hex::<String>()
                == "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312",
        );
        assert!(message.message_id.event_index == 1u64);
        assert!(message.destination_chain == "ethereum");
        assert!(
            message.source_address.to_bech32_string().unwrap()
                == "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7"
        );
    }

    // Should not handle event if it is not a poll started event
    #[async_test]
    async fn not_poll_started_event() {
        let event = into_structured_event(
            cosmwasm_std::Event::new("transfer"),
            &TMAddress::random(PREFIX),
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            MockMvxProxy::new(),
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if it is not emitted from voting verifier
    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = into_structured_event(
            poll_started_event(participants(5, None)),
            &TMAddress::random(PREFIX),
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            MockMvxProxy::new(),
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if worker is not a poll participant
    #[async_test]
    async fn verifier_is_not_a_participant() {
        let voting_verifier = TMAddress::random(PREFIX);
        let event =
            into_structured_event(poll_started_event(participants(5, None)), &voting_verifier);

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            voting_verifier,
            MockMvxProxy::new(),
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    #[async_test]
    async fn should_vote_correctly() {
        let mut proxy = MockMvxProxy::new();
        proxy
            .expect_transactions_info_with_results()
            .returning(|_| HashMap::new());

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(5, Some(worker.clone()))),
            &voting_verifier,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            proxy,
            watch::channel(0).1,
            monitoring_client,
        );

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_record_verification_vote_metric() {
        let mut proxy = MockMvxProxy::new();
        proxy
            .expect_transactions_info_with_results()
            .returning(|_| HashMap::new());

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(2, Some(worker.clone()))),
            &voting_verifier,
        );

        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            proxy,
            watch::channel(0).1,
            monitoring_client,
        );

        let _ = handler.handle(&event).await.unwrap();

        let metrics = receiver.recv().await.unwrap();
        assert_eq!(
            metrics,
            MetricsMsg::VerificationVote {
                vote_decision: Vote::NotFound,
                chain_name: MULTIVERSX_CHAIN_NAME.clone(),
            }
        );

        assert!(receiver.try_recv().is_err());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut proxy = MockMvxProxy::new();
        proxy
            .expect_transactions_info_with_results()
            .returning(|_| HashMap::new());

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(5, Some(worker.clone()))),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let (monitoring_client, _) = test_utils::monitoring_client();

        let handler = super::Handler::new(worker, voting_verifier, proxy, rx, monitoring_client);

        // poll is not expired yet, should hit proxy
        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    fn poll_started_event(participants: Vec<TMAddress>) -> PollStarted {
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "multiversx".parse().unwrap(),
                source_gateway_address:
                    "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx"
                        .parse()
                        .unwrap(),
                confirmation_height: 15,
                expires_at: 100,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            #[allow(deprecated)] // TODO: The below event uses the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            messages: vec![TxEventConfirmation {
                tx_id: "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312"
                    .parse()
                    .unwrap(),
                event_index: 1,
                message_id:
                    "0xdfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312-1"
                .to_string()
                .parse()
                .unwrap(),
                source_address: "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7"
                    .parse()
                    .unwrap(),
                destination_chain: "ethereum".parse().unwrap(),
                destination_address: format!("0x{:x}", H160::repeat_byte(2)).parse().unwrap(),
                payload_hash: [1;32],
            }],
        }
    }
}

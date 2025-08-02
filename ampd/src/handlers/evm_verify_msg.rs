use std::collections::{HashMap, HashSet};
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use ethers_core::types::{TransactionReceipt, U64};
use events::try_from;
use events::Error::EventTypeMismatch;
use futures::future::join_all;
use router_api::ChainName;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::evm::finalizer;
use crate::evm::finalizer::Finalization;
use crate::evm::json_rpc::EthereumClient;
use crate::evm::verifier::verify_message;
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::monitoring;
use crate::monitoring::metrics::Msg as MetricsMsg;
use crate::types::{EVMAddress, Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub message_id: HexTxHashAndEventIndex,
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_address: EVMAddress,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: EVMAddress,
    confirmation_height: u64,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

#[derive(Debug)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    chain: ChainName,
    finalizer_type: Finalization,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
    monitoring_client: monitoring::Client,
}

impl<C> Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        chain: ChainName,
        finalizer_type: Finalization,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
        monitoring_client: monitoring::Client,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            chain,
            finalizer_type,
            rpc_client,
            latest_block_height,
            monitoring_client,
        }
    }

    async fn finalized_tx_receipts<T>(
        &self,
        tx_hashes: T,
        confirmation_height: u64,
    ) -> Result<HashMap<Hash, TransactionReceipt>>
    where
        T: IntoIterator<Item = Hash>,
    {
        let latest_finalized_block_height =
            finalizer::pick(&self.finalizer_type, &self.rpc_client, confirmation_height)
                .latest_finalized_block_height()
                .await
                .change_context(Error::Finalizer)?;

        Ok(join_all(
            tx_hashes
                .into_iter()
                .map(|tx_hash| self.rpc_client.transaction_receipt(tx_hash)),
        )
        .await
        .into_iter()
        .filter_map(std::result::Result::unwrap_or_default)
        .filter_map(|tx_receipt| {
            if tx_receipt
                .block_number
                .unwrap_or(U64::MAX)
                .le(&latest_finalized_block_height)
            {
                Some((tx_receipt.transaction_hash, tx_receipt))
            } else {
                None
            }
        })
        .collect())
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
impl<C> EventHandler for Handler<C>
where
    C: EthereumClient + Send + Sync,
{
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
            confirmation_height,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(DeserializeEvent)?,
        };

        if self.chain != source_chain {
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

        let tx_hashes: HashSet<Hash> = messages
            .iter()
            .map(|msg| msg.message_id.tx_hash.into())
            .collect();
        let finalized_tx_receipts = self
            .finalized_tx_receipts(tx_hashes, confirmation_height)
            .await?;

        let poll_id_str: String = poll_id.into();
        let source_chain_str: String = source_chain.into();

        let votes = info_span!(
            "verify messages from an EVM chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
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
                        .get(&msg.message_id.tx_hash.into())
                        .map_or(Vote::NotFound, |tx_receipt| {
                            verify_message(&source_gateway_address, tx_receipt, msg)
                        })
                })
                .inspect(|vote| {
                    self.monitoring_client
                        .metrics()
                        .record_metric(MetricsMsg::VerificationVote {
                            vote_decision: vote.clone(),
                            chain_name: self.chain.clone(),
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
    use std::convert::TryInto;
    use std::str::FromStr;

    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::voting::Vote;
    use cosmwasm_std;
    use error_stack::{Report, Result};
    use ethers_core::types::{Block, H160, H256, U64};
    use ethers_providers::ProviderError;
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use router_api::ChainName;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::evm::finalizer::Finalization;
    use crate::evm::json_rpc::MockEthereumClient;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::monitoring::metrics::Msg as MetricsMsg;
    use crate::monitoring::test_utils;
    use crate::types::{Hash, TMAddress};
    use crate::PREFIX;

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let msg_ids = [
            HexTxHashAndEventIndex::new(H256::repeat_byte(1), 0u64),
            HexTxHashAndEventIndex::new(H256::repeat_byte(2), 1u64),
            HexTxHashAndEventIndex::new(H256::repeat_byte(3), 10u64),
        ];
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "ethereum".parse().unwrap(),
                source_gateway_address: "0x4f4495243837681061c4743b74eedf548d5686a5"
                    .parse()
                    .unwrap(),
                confirmation_height: 15,
                expires_at,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            #[allow(deprecated)] // TODO: The below events use the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            messages: vec![
                TxEventConfirmation {
                    tx_id: msg_ids[0].tx_hash_as_hex(),
                    event_index: u32::try_from(msg_ids[0].event_index).unwrap(),
                    message_id: msg_ids[0].to_string().parse().unwrap(),
                    source_address: format!("0x{:x}", H160::repeat_byte(1)).parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", H160::repeat_byte(2)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(4).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    tx_id: msg_ids[1].tx_hash_as_hex(),
                    event_index: u32::try_from(msg_ids[1].event_index).unwrap(),
                    message_id: msg_ids[1].to_string().parse().unwrap(),
                    source_address: format!("0x{:x}", H160::repeat_byte(3)).parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", H160::repeat_byte(4)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(5).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    tx_id: msg_ids[2].tx_hash_as_hex(),
                    event_index: u32::try_from(msg_ids[2].event_index).unwrap(),
                    message_id: msg_ids[2].to_string().parse().unwrap(),
                    source_address: format!("0x{:x}", H160::repeat_byte(5)).parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", H160::repeat_byte(6)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(6).to_fixed_bytes(),
                },
            ],
        }
    }

    #[test]
    fn should_not_deserialize_incorrect_event() {
        // incorrect event type
        let mut event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut event_type, ..
            } => {
                *event_type = "incorrect".into();
            }
            _ => panic!("incorrect event type"),
        }
        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            EventTypeMismatch(_)
        ));

        // invalid field
        let mut event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        match event {
            Event::Abci {
                ref mut attributes, ..
            } => {
                attributes.insert("source_gateway_address".into(), "invalid".into());
            }
            _ => panic!("incorrect event type"),
        }

        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            DeserializationFailed(_, _)
        ));
    }

    #[test]
    fn evm_verify_msg_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        let event: PollStartedEvent = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut rpc_client = MockEthereumClient::new();
        // mock the rpc client as erroring. If the handler successfully ignores the poll, we won't hit this
        rpc_client.expect_finalized_block().returning(|| {
            Err(Report::from(ProviderError::CustomError(
                "failed to get finalized block".to_string(),
            )))
        });

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier_contract,
        );

        let (monitoring_client, _) = test_utils::monitoring_client();

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(
            verifier,
            voting_verifier_contract,
            ChainName::from_str("ethereum").unwrap(),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            rx,
            monitoring_client,
        );

        // poll is not expired yet, should hit rpc error
        assert!(handler.handle(&event).await.is_err());

        let _ = tx.send(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn should_record_verification_vote_metric() {
        let mut rpc_client = MockEthereumClient::new();
        let mut block = Block::<Hash>::default();
        let block_number: U64 = 10.into();
        block.number = Some(block_number);

        rpc_client
            .expect_finalized_block()
            .returning(move || Ok(block.clone()));

        rpc_client
            .expect_transaction_receipt()
            .returning(|_| Ok(None));

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let event: Event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier_contract,
        );
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let handler = super::Handler::new(
            verifier,
            voting_verifier_contract,
            ChainName::from_str("ethereum").unwrap(),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            watch::channel(0).1,
            monitoring_client,
        );

        assert!(handler.handle(&event).await.is_ok());

        for _ in 0..3 {
            let metrics = receiver.recv().await.unwrap();

            assert_eq!(
                metrics,
                MetricsMsg::VerificationVote {
                    vote_decision: Vote::NotFound,
                    chain_name: ChainName::from_str("ethereum").unwrap(),
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }
}

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
use router_api::{Address, ChainName};
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use event_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::evm::finalizer;
use crate::evm::finalizer::Finalization;
use crate::evm::json_rpc::EthereumClient;
use crate::evm::verifier::verify_event;
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::types::{EVMAddress, Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Event {
    pub message_id: HexTxHashAndEventIndex,
    pub source_chain: ChainName,
    pub contract_address: Address,
    pub event_data: event_verifier::msg::EventData,
}


#[derive(Deserialize, Debug)]
#[try_from("wasm-events_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: EVMAddress,
    confirmation_height: u64,
    expires_at: u64,
    events: Vec<Event>,
    participants: Vec<TMAddress>,
}

#[derive(Debug)]
pub struct Handler<C>
where
    C: EthereumClient,
{
    verifier: TMAddress,
    event_verifier_contract: TMAddress,
    chain: ChainName,
    finalizer_type: Finalization,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
}

impl<C> Handler<C>
where
    C: EthereumClient + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        event_verifier_contract: TMAddress,
        chain: ChainName,
        finalizer_type: Finalization,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            event_verifier_contract,
            chain,
            finalizer_type,
            rpc_client,
            latest_block_height,
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
            println!("tx_receipt: {:?}", tx_receipt);
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
            contract: self.event_verifier_contract.as_ref().clone(),
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
        if !event.is_from_contract(self.event_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        println!("event: {:?}", event);
        let PollStartedEvent {
            poll_id,
            source_chain,
            source_gateway_address,
            events,
            expires_at,
            confirmation_height,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(DeserializeEvent)?,
        };
        println!("event: {:?}", event);

        if self.chain != source_chain {
            println!("not the same chain");
            return Ok(vec![]);
        }

        if !participants.contains(&self.verifier) {
            println!("not a participant");
            return Ok(vec![]);
        }
        println!("processing event");

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let tx_hashes: HashSet<Hash> = events
            .iter()
            .map(|evt| evt.message_id.tx_hash.into())
            .collect();
        println!("tx_hashes: {:?}", tx_hashes);
        let finalized_tx_receipts = self
            .finalized_tx_receipts(tx_hashes, confirmation_height)
            .await?;
        println!("finalized_tx_receipts: {:?}", finalized_tx_receipts);

        let poll_id_str: String = poll_id.into();
        let source_chain_str: String = source_chain.into();
        let votes = info_span!(
            "verify events from an EVM chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            event_ids = events
                .iter()
                .map(|evt| evt.message_id.to_string())
                .collect::<Vec<String>>()
                .as_value(),
        )
        .in_scope(|| {
            info!("ready to verify events in poll",);

            let votes: Vec<_> = events
                .iter()
                .map(|evt| {
                    finalized_tx_receipts
                        .get(&evt.message_id.tx_hash.into())
                        .map_or(Vote::NotFound, |tx_receipt| {
                            verify_event(&source_gateway_address, tx_receipt, evt)
                        })
                })
                .collect();
            info!(
                votes = votes.as_value(),
                "ready to vote for events in poll"
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
    use cosmwasm_std;
    use error_stack::{Report, Result};
    use ethers_core::types::{H160, H256};
    use ethers_providers::ProviderError;
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use router_api::ChainName;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use event_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::evm::finalizer::Finalization;
    use crate::evm::json_rpc::MockEthereumClient;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::types::TMAddress;
    use crate::PREFIX;

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let msg_ids = [
            HexTxHashAndEventIndex::new(H256::repeat_byte(1), 0u64),
            HexTxHashAndEventIndex::new(H256::repeat_byte(2), 1u64),
            HexTxHashAndEventIndex::new(H256::repeat_byte(3), 10u64),
        ];
        PollStarted::Events {
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
            events: vec![
                TxEventConfirmation {
                    tx_id: msg_ids[0].tx_hash_as_hex(),
                    event_index: u32::try_from(msg_ids[0].event_index).unwrap(),
                    message_id: msg_ids[0].to_string().parse().unwrap(),
                    source_chain: "ethereum".parse().unwrap(),
                    contract_address: format!("0x{:x}", H160::repeat_byte(1)).parse().unwrap(),
                    event_data: event_verifier::msg::EventData::Evm {
                        topics: vec![cosmwasm_std::HexBinary::from(vec![1, 2, 3])],
                        data: cosmwasm_std::HexBinary::from(vec![1, 2, 3, 4]),
                    },
                },
                TxEventConfirmation {
                    tx_id: msg_ids[1].tx_hash_as_hex(),
                    event_index: u32::try_from(msg_ids[1].event_index).unwrap(),
                    message_id: msg_ids[1].to_string().parse().unwrap(),
                    source_chain: "ethereum".parse().unwrap(),
                    contract_address: format!("0x{:x}", H160::repeat_byte(3)).parse().unwrap(),
                    event_data: event_verifier::msg::EventData::Evm {
                        topics: vec![cosmwasm_std::HexBinary::from(vec![1, 2, 3])],
                        data: cosmwasm_std::HexBinary::from(vec![5, 6, 7, 8]),
                    },
                },
                TxEventConfirmation {
                    tx_id: msg_ids[2].tx_hash_as_hex(),
                    event_index: u32::try_from(msg_ids[2].event_index).unwrap(),
                    message_id: msg_ids[2].to_string().parse().unwrap(),
                    source_chain: "ethereum".parse().unwrap(),
                    contract_address: format!("0x{:x}", H160::repeat_byte(5)).parse().unwrap(),
                    event_data: event_verifier::msg::EventData::Evm {
                        topics: vec![cosmwasm_std::HexBinary::from(vec![1, 2, 3])],
                        data: cosmwasm_std::HexBinary::from(vec![9, 10, 11, 12]),
                    },
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
    fn evm_verify_event_should_deserialize_correct_event() {
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

        let event_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &event_verifier_contract,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(
            verifier,
            event_verifier_contract,
            ChainName::from_str("ethereum").unwrap(),
            Finalization::RPCFinalizedBlock,
            rpc_client,
            rx,
        );

        // poll is not expired yet, should hit rpc error
        assert!(handler.handle(&event).await.is_err());

        let _ = tx.send(expiration + 1);

        // poll is expired, should not hit rpc error now
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }
} 
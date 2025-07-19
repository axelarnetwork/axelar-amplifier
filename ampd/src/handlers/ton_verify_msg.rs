use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::try_from;
use events::Error::EventTypeMismatch;
use router_api::ChainName;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tonlib_core::TonAddress;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::handlers::errors::Error::DeserializeEvent;
use crate::ton::rpc::TonClient;
use crate::ton::verifier::verify_call_contract;
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

pub mod hex_tx_hash_string {
    use std::str::FromStr;

    use axelar_wasm_std::msg_id::HexTxHash;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HexTxHash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        HexTxHash::from_str(&string).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct Message {
    #[serde(with = "hex_tx_hash_string")]
    pub message_id: HexTxHash,
    pub destination_address: String,
    pub destination_chain: ChainName,
    pub source_address: TonAddress,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: TonAddress,
    confirmation_height: u64,
    expires_at: u64,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FetchingError {
    #[error("RPC error")]
    Client,
    #[error("invalid call")]
    InvalidCall,
    #[error("transaction not found on chain")]
    NotFound,
}

pub struct Handler<C>
where
    C: TonClient,
{
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    rpc_client: C,
    latest_block_height: Receiver<u64>,
}

impl<C> Handler<C>
where
    C: TonClient + Send + Sync,
{
    pub fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        rpc_client: C,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            voting_verifier_contract,
            rpc_client,
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
impl<C> EventHandler for Handler<C>
where
    C: TonClient + Send + Sync,
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
            confirmation_height: _,
            participants,
        } = match event.try_into() as error_stack::Result<_, _> {
            Err(report) if matches!(report.current_context(), EventTypeMismatch(_)) => {
                return Ok(vec![])
            }
            event => event.change_context(DeserializeEvent)?,
        };

        if !participants.contains(&self.verifier) {
            return Ok(vec![]);
        }
        let latest_block_height = *self.latest_block_height.borrow();

        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(vec![]);
        }

        let poll_id_str: String = poll_id.into();
        let source_chain_str: String = source_chain.into();

        let votes = info_span!(
            "verify messages from Ton",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            message_ids = messages
                .iter()
                .map(|msg| msg.message_id.to_string())
                .collect::<Vec<String>>()
                .as_value(),
        )
        .in_scope(|| async {
            info!("ready to verify messages in poll",);

            let mut votes = Vec::new();

            for m in messages.iter() {
                let log = self
                    .rpc_client
                    .get_log(&source_gateway_address, &m.message_id)
                    .await;
                if log.is_err() {
                    votes.push(Vote::NotFound); // Vote no
                } else {
                    let log = log.unwrap();

                    let vote = match verify_call_contract(log, m) {
                        true => Vote::SucceededOnChain,
                        false => Vote::FailedOnChain,
                    };

                    votes.push(vote);
                }
            }
            info!(
                votes = votes.as_value(),
                "ready to vote for messages in poll"
            );

            votes
        });

        Ok(vec![self
            .vote_msg(poll_id, votes.await)
            .into_any()
            .expect("vote msg should serialize")])
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use axelar_wasm_std::msg_id::HexTxHash;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmwasm_std;
    use error_stack::Result;
    use ethers_core::types::{H160, H256};
    use events::Error::{DeserializationFailed, EventTypeMismatch};
    use events::Event;
    use router_api::{CrossChainId, Message};
    use serde_json::Value;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use ton_utils::build_call_contract_log_cell;
    use tonlib_core::TonAddress;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::*;
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::handlers::ton_verify_msg::FetchingError;
    use crate::ton::rpc::{TonClient, TonLog, TonRpcClient};
    use crate::ton::verifier::OP_CALL_CONTRACT;
    use crate::types::TMAddress;
    use crate::PREFIX;

    fn poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        let msg_ids = [
            HexTxHash::new(H256::repeat_byte(1)),
            HexTxHash::new(H256::repeat_byte(2)),
            HexTxHash::new(H256::repeat_byte(3)),
        ];
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "ethereum".parse().unwrap(),
                source_gateway_address: "kQAAGUqtjkIr7fQ_7nRtbZKdNp26slRopp1RNwbqaXi2OnXH"
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
                    event_index: 0u32,
                    message_id: msg_ids[0].to_string().parse().unwrap(),
                    source_address: "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe".parse().unwrap(), // must not contain a _ symbol!
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", H160::repeat_byte(2)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(4).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    tx_id: msg_ids[1].tx_hash_as_hex(),
                    event_index: 0u32,
                    message_id: msg_ids[1].to_string().parse().unwrap(),
                    source_address: "0:7c3b4249fa1a9e0c0a830b5386eb33d805fa55f90cf03de77492971b20b5ec98".parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", H160::repeat_byte(4)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(5).to_fixed_bytes(),
                },
                TxEventConfirmation {
                    tx_id: msg_ids[2].tx_hash_as_hex(),
                    event_index: 0u32,
                    message_id: msg_ids[2].to_string().parse().unwrap(),
                    source_address: "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe".parse().unwrap(),
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

        assert!(matches!(event, Event::Abci { .. }));
        match event {
            Event::Abci {
                ref mut event_type, ..
            } => {
                *event_type = "incorrect".into();
            }
            _ => unreachable!("Variant already checked"),
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

        assert!(matches!(event, Event::Abci { .. }));
        match event {
            Event::Abci {
                ref mut attributes, ..
            } => {
                attributes.insert("source_gateway_address".into(), "invalid".into());
            }
            _ => unreachable!("Variant already checked"),
        }

        let event: Result<PollStartedEvent, events::Error> = (&event).try_into();

        assert!(matches!(
            event.unwrap_err().current_context(),
            DeserializationFailed(_, _)
        ));
    }

    #[test]
    fn ton_verify_msg_should_deserialize_correct_event() {
        let event: Event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &TMAddress::random(PREFIX),
        );
        println!("{:?}", event);
        let event: PollStartedEvent = event.try_into().unwrap();

        goldie::assert_debug!(event);
    }

    #[async_test]
    async fn ton_verify_msg_should_skip_expired_poll() {
        let rpc_client = TonRpcClient::new("inv-scheme://invalid-url");

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event: Event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), expiration),
            &voting_verifier_contract,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        // poll is not expired yet, should get one vote
        let vote = handler.handle(&event).await.unwrap();
        assert_eq!(vote.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired, should not get a vote
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn ton_verify_msg_should_skip_not_poll_started_event() {
        let rpc_client = TonRpcClient::new("inv-scheme://invalid-url");

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            cosmwasm_std::Event::new("transfer"), // not a poll started event
            &voting_verifier_contract,
        );

        let (_tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn ton_verify_msg_should_skip_poll_not_from_voting_verifier() {
        let rpc_client = TonRpcClient::new("inv-scheme://invalid-url");

        let voting_verifier_contract = TMAddress::random(PREFIX);
        let other_contract = TMAddress::random(PREFIX);

        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), 100),
            &other_contract,
        );

        let (_tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn ton_verify_msg_should_skip_poll_when_verifier_is_not_participant() {
        let rpc_client = TonRpcClient::new("inv-scheme://invalid-url");

        let voting_verifier_contract = TMAddress::random(PREFIX);

        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(5, None), 100),
            &voting_verifier_contract,
        );

        let (_tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    #[async_test]
    async fn ton_verify_msg_should_vote_correctly() {
        let rpc_client = ValidResponseTonRpc;

        let voting_verifier_contract = TMAddress::random(PREFIX);

        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier_contract,
        );

        let (_tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        let msg_execute_contract = MsgExecuteContract::from_any(actual.first().unwrap()).unwrap();

        let json_str = String::from_utf8(msg_execute_contract.msg).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        goldie::assert_json!(parsed);
    }

    #[async_test]
    async fn ton_verify_msg_should_vote_no_on_rpc_failure() {
        let rpc_client = TonRpcClient::new("inv-scheme://invalid-url");

        let voting_verifier_contract = TMAddress::random(PREFIX);

        let verifier = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(5, Some(verifier.clone())), 100),
            &voting_verifier_contract,
        );

        let (_tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(verifier, voting_verifier_contract, rpc_client, rx);

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        let msg_execute_contract = MsgExecuteContract::from_any(actual.first().unwrap()).unwrap();

        let json_str = String::from_utf8(msg_execute_contract.msg).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        goldie::assert_json!(parsed);
    }

    struct ValidResponseTonRpc;
    #[async_trait::async_trait]
    impl TonClient for ValidResponseTonRpc {
        #[inline(never)]
        async fn get_log(
            &self,
            _contract_address: &TonAddress,
            tx_hash: &HexTxHash,
        ) -> error_stack::Result<TonLog, FetchingError> {
            let msgs = vec![
                // This correct message matches the first TxEventConfirmation in the simulated event
                // The vote for the first message should thus be SucceededOnChain
                Message {
                    cc_id: CrossChainId {
                        source_chain: "ton".parse().unwrap(),
                        message_id: HexTxHash::new(H256::repeat_byte(1)).tx_hash_as_hex(),
                    },
                    source_address:
                        "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe"
                            .parse()
                            .unwrap(), // must not contain a _ symbol!
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", H160::repeat_byte(2)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(4).to_fixed_bytes(),
                },
                // This message has the same cc_id as the second TxEventConfirmation, but differs
                // in the destination address. The vote for the second message should thus be FailedOnChain
                Message {
                    cc_id: CrossChainId {
                        source_chain: "ton".parse().unwrap(),
                        message_id: HexTxHash::new(H256::repeat_byte(2)).tx_hash_as_hex(),
                    },
                    source_address:
                        "0:7c3b4249fa1a9e0c0a830b5386eb33d805fa55f90cf03de77492971b20b5ec98"
                            .parse()
                            .unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", H160::repeat_byte(42)).parse().unwrap(),
                    payload_hash: H256::repeat_byte(5).to_fixed_bytes(),
                },
                // For the third TxEventConfirmation, there is no matching call contract log.
                // The vote for the third message should thus be NotFound
            ];

            let queried_msg = msgs
                .iter()
                .find(|msg| tx_hash.to_string() == *msg.cc_id.message_id);
            match queried_msg {
                Some(msg) => Ok(TonLog {
                    opcode: OP_CALL_CONTRACT,
                    cell: build_call_contract_log_cell(msg, vec![]).unwrap().to_arc(),
                }),
                None => Err(FetchingError::NotFound)?,
            }
        }
    }
}

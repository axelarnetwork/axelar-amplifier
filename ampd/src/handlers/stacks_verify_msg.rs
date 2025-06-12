use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::voting::{PollId, Vote};
use clarity::vm::types::PrincipalData;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::{try_from, Event};
use router_api::ChainName;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::stacks::finalizer::latest_finalized_block_height;
use crate::stacks::http_client::Client;
use crate::stacks::verifier::verify_message;
use crate::types::{Hash, TMAddress};

type CustomResult<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub message_id: HexTxHashAndEventIndex,
    pub destination_address: String,
    pub destination_chain: ChainName,
    #[serde(with = "crate::stacks::principal_data_serde")]
    pub source_address: PrincipalData,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    #[serde(with = "crate::stacks::principal_data_serde")]
    source_gateway_address: PrincipalData,
    confirmation_height: u64,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler {
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    http_client: Client,
    latest_block_height: Receiver<u64>,
}

impl Handler {
    pub async fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        http_client: Client,
        latest_block_height: Receiver<u64>,
    ) -> error_stack::Result<Self, crate::stacks::http_client::Error> {
        Ok(Self {
            verifier,
            voting_verifier_contract,
            http_client,
            latest_block_height,
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
}

#[async_trait]
impl EventHandler for Handler {
    type Err = Error;

    async fn handle(&self, event: &Event) -> CustomResult<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
            source_gateway_address,
            confirmation_height,
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

        let latest_finalized_block_height =
            latest_finalized_block_height(&self.http_client, confirmation_height)
                .await
                .change_context(Error::Finalizer)?;

        let tx_hashes: HashSet<Hash> = messages
            .iter()
            .map(|message| message.message_id.tx_hash.into())
            .collect();
        let transactions = self
            .http_client
            .finalized_transactions(tx_hashes, latest_finalized_block_height)
            .await;

        let message_ids = messages
            .iter()
            .map(|message| message.message_id.to_string())
            .collect::<Vec<_>>();

        let votes = info_span!(
            "verify messages in poll",
            poll_id = poll_id.to_string(),
            source_chain = source_chain.to_string(),
            message_ids = message_ids.as_value()
        )
        .in_scope(|| {
            info!("ready to verify messages in poll",);

            let votes: Vec<Vote> = messages
                .iter()
                .map(|msg| {
                    transactions
                        .get(&msg.message_id.tx_hash.into())
                        .map_or(Vote::NotFound, |transaction| {
                            verify_message(&source_gateway_address, transaction, msg)
                        })
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

    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use cosmwasm_std;
    use error_stack::Result;
    use ethers_core::types::H160;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::{Handler, Message, PollStartedEvent};
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::{into_structured_event, participants};
    use crate::stacks::http_client::{Block, Client};
    use crate::types::{Hash, TMAddress};
    use crate::PREFIX;

    #[test]
    fn stacks_should_deserialize_poll_started_event() {
        let event: Result<PollStartedEvent, events::Error> = into_structured_event(
            poll_started_event(participants(5, None)),
            &TMAddress::random(PREFIX),
        )
        .try_into();

        assert!(event.is_ok());

        let event = event.unwrap();

        goldie::assert_debug!(&event);

        assert!(event.poll_id == 100u64.into());
        assert!(
            event.source_gateway_address.to_string()
                == "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway"
        );
        assert!(event.confirmation_height == 15);

        let message: &Message = event.messages.first().unwrap();

        assert!(message.message_id.event_index == 1u64);
        assert!(message.destination_chain == "ethereum");
        assert!(message.source_address.to_string() == "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    }

    // Should not handle event if it is not a poll started event
    #[async_test]
    async fn not_poll_started_event() {
        let event = into_structured_event(
            cosmwasm_std::Event::new("transfer"),
            &TMAddress::random(PREFIX),
        );

        let handler = test_handler().await;

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if it is not emitted from voting verifier
    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = into_structured_event(
            poll_started_event(participants(5, None)),
            &TMAddress::random(PREFIX),
        );

        let handler = test_handler().await;

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if worker is not a poll participant
    #[async_test]
    async fn verifier_is_not_a_participant() {
        let client = Client::faux();

        let voting_verifier = TMAddress::random(PREFIX);
        let event =
            into_structured_event(poll_started_event(participants(5, None)), &voting_verifier);

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            voting_verifier,
            client,
            watch::channel(0).1,
        )
        .await
        .unwrap();

        assert!(handler.handle(&event).await.is_ok());
    }

    #[async_test]
    async fn should_vote_correctly() {
        let mut client = Client::faux();
        faux::when!(client.latest_block).then(|_| Ok(Block { height: 1 }));
        faux::when!(client.finalized_transactions).then(|_| HashMap::new());

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(5, Some(worker.clone()))),
            &voting_verifier,
        );

        let handler = super::Handler::new(worker, voting_verifier, client, watch::channel(0).1)
            .await
            .unwrap();

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut client = Client::faux();
        faux::when!(client.latest_block).then(|_| Ok(Block { height: 1 }));
        faux::when!(client.finalized_transactions).then(|_| HashMap::new());

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(5, Some(worker.clone()))),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(worker, voting_verifier, client, rx)
            .await
            .unwrap();

        // poll is not expired yet, should hit proxy
        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    async fn test_handler() -> Handler {
        let client = Client::faux();

        let handler = Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            client,
            watch::channel(0).1,
        )
        .await
        .unwrap();

        handler
    }

    fn poll_started_event(participants: Vec<TMAddress>) -> PollStarted {
        let msg_id = HexTxHashAndEventIndex::new(Hash::from([3; 32]), 1u64);

        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "stacks".parse().unwrap(),
                source_gateway_address: "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway"
                    .parse()
                    .unwrap(),
                confirmation_height: 15,
                expires_at: 100,
                participants: participants
                    .into_iter()
                    .map(|addr| cosmwasm_std::Addr::unchecked(addr.to_string()))
                    .collect(),
            },
            #[allow(
                deprecated
            )] // TODO: The below events use the deprecated tx_id and event_index fields. Remove this attribute when those fields are removed
            messages: vec![TxEventConfirmation {
                tx_id: msg_id.tx_hash_as_hex(),
                event_index: u32::try_from(msg_id.event_index).unwrap(),
                message_id: msg_id.to_string().parse().unwrap(),
                source_address: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM".parse().unwrap(),
                destination_chain: "ethereum".parse().unwrap(),
                destination_address: format!("0x{:x}", H160::repeat_byte(2)).parse().unwrap(),
                payload_hash: [1; 32],
            }],
        }
    }
}

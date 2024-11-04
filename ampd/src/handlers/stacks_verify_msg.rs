use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use axelar_wasm_std::voting::{PollId, Vote};
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::tx::Msg;
use cosmrs::Any;
use error_stack::ResultExt;
use events::Error::EventTypeMismatch;
use events::Event;
use events_derive::try_from;
use futures::future;
use router_api::ChainName;
use serde::Deserialize;
use tokio::sync::watch::Receiver;
use tracing::info;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::stacks::http_client::{Client, Transaction};
use crate::stacks::verifier::verify_message;
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub tx_id: Hash,
    pub event_index: u32,
    pub destination_address: String,
    pub destination_chain: router_api::ChainName,
    pub source_address: String,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    poll_id: PollId,
    source_chain: ChainName,
    source_gateway_address: String,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler {
    verifier: TMAddress,
    voting_verifier_contract: TMAddress,
    http_client: Client,
    latest_block_height: Receiver<u64>,
    its_address: String,
    reference_native_interchain_token_code: String,
    reference_token_manager_code: String,
}

impl Handler {
    pub async fn new(
        verifier: TMAddress,
        voting_verifier_contract: TMAddress,
        http_client: Client,
        latest_block_height: Receiver<u64>,
        its_address: String,
        reference_native_interchain_token_address: String,
        reference_token_manager_address: String,
    ) -> error_stack::Result<Self, crate::stacks::http_client::Error> {
        let reference_native_interchain_token_info = http_client
            .get_contract_info(reference_native_interchain_token_address.as_str())
            .await?;

        let reference_token_manager_info = http_client
            .get_contract_info(reference_token_manager_address.as_str())
            .await?;

        Ok(Self {
            verifier,
            voting_verifier_contract,
            http_client,
            latest_block_height,
            its_address,
            reference_native_interchain_token_code: reference_native_interchain_token_info
                .source_code,
            reference_token_manager_code: reference_token_manager_info.source_code,
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

    async fn handle(&self, event: &Event) -> Result<Vec<Any>> {
        if !event.is_from_contract(self.voting_verifier_contract.as_ref()) {
            return Ok(vec![]);
        }

        let PollStartedEvent {
            poll_id,
            source_chain,
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

        let tx_hashes: HashSet<_> = messages.iter().map(|message| message.tx_id).collect();
        let transactions = self.http_client.get_transactions(tx_hashes).await;

        let futures = messages.iter().map(|msg| async {
            match transactions.get(&msg.tx_id) {
                Some(transaction) => {
                    verify_message(
                        &source_chain,
                        &source_gateway_address,
                        &self.its_address,
                        transaction,
                        msg,
                        &self.http_client,
                        &self.reference_native_interchain_token_code,
                        &self.reference_token_manager_code,
                    )
                    .await
                }
                None => Vote::NotFound,
            }
        });

        let votes: Vec<Vote> = future::join_all(futures).await;

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

    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmrs::tx::Msg;
    use cosmwasm_std;
    use error_stack::Result;
    use tokio::sync::watch;
    use tokio::test as async_test;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::{Handler, PollStartedEvent};
    use crate::event_processor::EventHandler;
    use crate::handlers::tests::into_structured_event;
    use crate::stacks::http_client::{Client, ContractInfo};
    use crate::types::{EVMAddress, Hash, TMAddress};
    use crate::PREFIX;

    #[test]
    fn should_deserialize_poll_started_event() {
        let event: Result<PollStartedEvent, events::Error> = into_structured_event(
            poll_started_event(participants(5, None)),
            &TMAddress::random(PREFIX),
        )
        .try_into();

        assert!(event.is_ok());

        let event = event.unwrap();

        assert!(event.poll_id == 100u64.into());
        assert!(
            event.source_gateway_address
                == "SP2N959SER36FZ5QT1CX9BR63W3E8X35WQCMBYYWC.axelar-gateway"
        );

        let message = event.messages.first().unwrap();

        assert!(
            message.tx_id
                == "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
                    .parse()
                    .unwrap(),
        );
        assert!(message.event_index == 1u32);
        assert!(message.destination_chain == "ethereum");
        assert!(message.source_address == "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    }

    // Should not handle event if it is not a poll started event
    #[async_test]
    async fn not_poll_started_event() {
        let event = into_structured_event(
            cosmwasm_std::Event::new("transfer"),
            &TMAddress::random(PREFIX),
        );

        let handler = get_handler().await;

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if it is not emitted from voting verifier
    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = into_structured_event(
            poll_started_event(participants(5, None)),
            &TMAddress::random(PREFIX),
        );

        let handler = get_handler().await;

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if worker is not a poll participant
    #[async_test]
    async fn verifier_is_not_a_participant() {
        let mut client = Client::faux();
        faux::when!(client.get_contract_info).then(|_| {
            Ok(ContractInfo {
                source_code: "()".to_string(),
            })
        });

        let voting_verifier = TMAddress::random(PREFIX);
        let event =
            into_structured_event(poll_started_event(participants(5, None)), &voting_verifier);

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            voting_verifier,
            client,
            watch::channel(0).1,
            "its_address".to_string(),
            "native_interchain_token_code".to_string(),
            "token_manager_code".to_string(),
        )
        .await
        .unwrap();

        assert!(handler.handle(&event).await.is_ok());
    }

    #[async_test]
    async fn should_vote_correctly() {
        let mut client = Client::faux();
        faux::when!(client.get_contract_info).then(|_| {
            Ok(ContractInfo {
                source_code: "()".to_string(),
            })
        });
        faux::when!(client.get_transactions).then(|_| HashMap::new());

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let event = into_structured_event(
            poll_started_event(participants(5, Some(worker.clone()))),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            client,
            watch::channel(0).1,
            "its_address".to_string(),
            "native_interchain_token_code".to_string(),
            "token_manager_code".to_string(),
        )
        .await
        .unwrap();

        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);
        assert!(MsgExecuteContract::from_any(actual.first().unwrap()).is_ok());
    }

    #[async_test]
    async fn should_skip_expired_poll() {
        let mut client = Client::faux();
        faux::when!(client.get_contract_info).then(|_| {
            Ok(ContractInfo {
                source_code: "()".to_string(),
            })
        });
        faux::when!(client.get_transactions).then(|_| HashMap::new());

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let event = into_structured_event(
            poll_started_event(participants(5, Some(worker.clone()))),
            &voting_verifier,
        );

        let (tx, rx) = watch::channel(expiration - 1);

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            client,
            rx,
            "its_address".to_string(),
            "native_interchain_token_code".to_string(),
            "token_manager_code".to_string(),
        )
        .await
        .unwrap();

        // poll is not expired yet, should hit proxy
        let actual = handler.handle(&event).await.unwrap();
        assert_eq!(actual.len(), 1);

        let _ = tx.send(expiration + 1);

        // poll is expired
        assert_eq!(handler.handle(&event).await.unwrap(), vec![]);
    }

    async fn get_handler() -> Handler {
        let mut client = Client::faux();
        faux::when!(client.get_contract_info).then(|_| {
            Ok(ContractInfo {
                source_code: "()".to_string(),
            })
        });

        let handler = Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            client,
            watch::channel(0).1,
            "its_address".to_string(),
            "native_interchain_token_code".to_string(),
            "token_manager_code".to_string(),
        )
        .await
        .unwrap();

        handler
    }

    fn poll_started_event(participants: Vec<TMAddress>) -> PollStarted {
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
            messages: vec![TxEventConfirmation {
                tx_id: "0xee0049faf8dde5507418140ed72bd64f73cc001b08de98e0c16a3a8d9f2c38cf"
                    .parse()
                    .unwrap(),
                event_index: 1,
                message_id: "0xdfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312-1"
                    .to_string()
                    .parse()
                    .unwrap(),
                source_address: "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM".parse().unwrap(),
                destination_chain: "ethereum".parse().unwrap(),
                destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                payload_hash: Hash::random().to_fixed_bytes(),
            }],
        }
    }

    fn participants(n: u8, worker: Option<TMAddress>) -> Vec<TMAddress> {
        (0..n)
            .map(|_| TMAddress::random(PREFIX))
            .chain(worker)
            .collect()
    }
}

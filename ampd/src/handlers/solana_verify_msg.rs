use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use cosmrs::{tx::Msg, Any};
use error_stack::ResultExt;
use futures::stream::FuturesOrdered;
use futures::StreamExt;
use router_api::ChainName;
use serde::Deserialize;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use std::convert::TryInto;
use std::str::FromStr;
use tracing::{error, info};

use axelar_wasm_std::voting::{PollId, Vote};
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use tokio::sync::watch::Receiver;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::solana::msg_verifier::verify_message;
use crate::solana::rpc_client::RpcCacheWrapper;
use crate::types::TMAddress;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug, PartialEq)]
pub struct Message {
    pub tx_id: String,
    pub event_index: u64,
    pub destination_address: String,
    pub destination_chain: router_api::ChainName,
    pub source_address: String,
    #[serde(with = "axelar_wasm_std::hex")]
    pub payload_hash: [u8; 32],
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollId,
    source_gateway_address: String,
    source_chain: ChainName,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler {
    verifier: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: RpcCacheWrapper,
    latest_block_height: Receiver<u64>,
}

impl Handler {
    pub fn new(
        verifier: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: RpcCacheWrapper,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            verifier,
            voting_verifier,
            rpc_client,
            latest_block_height,
        }
    }

    fn vote_msg(&self, poll_id: PollId, votes: Vec<Vote>) -> MsgExecuteContract {
        MsgExecuteContract {
            sender: self.verifier.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
            msg: serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
                .expect("vote msg should serialize"), // This should serialize as inputs are controlled.
            funds: vec![],
        }
    }

    async fn process_message(
        &self,
        msg: &Message,
        source_gateway_address: &String,
    ) -> Result<Vote> {
        let sol_tx_signature = match Signature::from_str(&msg.tx_id) {
            Ok(sig) => sig,
            Err(err) => {
                error!(
                    tx_id = msg.tx_id.to_string(),
                    err = err.to_string(),
                    "Cannot decode solana tx signature"
                );
                return Ok(Vote::FailedOnChain);
            }
        };

        let sol_tx = match self
            .rpc_client
            .get_transaction(&sol_tx_signature, UiTransactionEncoding::Json)
            .await
        {
            Ok(tx) => tx,
            Err(err) => match err.kind() {
                // When tx is not found a null is returned.
                solana_client::client_error::ClientErrorKind::SerdeJson(_) => {
                    error!(
                        tx_id = msg.tx_id,
                        err = err.to_string(),
                        "Cannot find solana tx signature"
                    );
                    return Ok(Vote::NotFound);
                }
                _ => {
                    error!(tx_id = msg.tx_id, "RPC error while fetching solana tx");
                    return Err(Error::TxReceipts)?;
                }
            },
        };
        Ok(verify_message(source_gateway_address, sol_tx, msg))
    }
}

#[async_trait]
impl EventHandler for Handler {
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<Vec<Any>> {
        let PollStartedEvent {
            contract_address,
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

        if self.voting_verifier != contract_address {
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

        let mut votes: Vec<Vote> = Vec::new();

        let mut ord_fut: FuturesOrdered<_> = messages
            .iter()
            .map(|msg| self.process_message(msg, &source_gateway_address))
            .collect();

        while let Some(vote_result) = ord_fut.next().await {
            votes.push(vote_result?) // If there is a failure, its due to a network error, so we abort this handler operation and all messages need to be processed again.
        }

        Ok(vec![self
            .vote_msg(poll_id, votes)
            .into_any()
            .expect("vote msg should serialize")])
    }
}

#[cfg(test)]
mod test {

    use std::num::NonZeroUsize;

    use base64::{engine::general_purpose::STANDARD, Engine};
    use events::Event;
    use solana_client::rpc_request::RpcRequest;
    use tendermint::abci;
    use tokio::sync::watch;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use crate::{
        solana::test_utils::rpc_client_with_recorder,
        types::{EVMAddress, Hash},
        PREFIX,
    };
    use tokio::test as async_test;

    use super::*;

    #[async_test]
    async fn must_correctly_broadcast_message_validation() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the message verifier
        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event(
                participants(5, Some(worker.clone())),
                100,
                "solana".parse().unwrap(),
            ),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            rx,
        );

        let votes = handler.handle(&event).await.unwrap();
        assert!(!votes.is_empty());
        assert_eq!(
            Some(&2),
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
    }

    #[async_test]
    async fn must_skip_duplicated_tx() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the message verifier
        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event_with_duplicates(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            rx,
        );

        let handle_result = handler.handle(&event).await.unwrap();
        assert!(!handle_result.is_empty());
        assert_eq!(
            Some(&1),
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
    }

    #[async_test]
    async fn ignores_poll_event_if_voting_verifier_address_not_match_event_address() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the message verifier
        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event(
                participants(5, Some(worker.clone())),
                100,
                "solana".parse().unwrap(),
            ),
            &TMAddress::random(PREFIX), // A different, unexpected address comes from the event.
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            rx,
        );

        let handler_result = handler.handle(&event).await.unwrap();
        assert!(handler_result.is_empty());
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
    }

    #[async_test]
    async fn ignores_poll_event_if_worker_not_part_of_participants() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the message verifier
        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event(participants(5, None), 100, "solana".parse().unwrap()), // This worker is not in participant set. So will skip the event.
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            rx,
        );

        let handler_result = handler.handle(&event).await.unwrap();
        assert!(handler_result.is_empty());
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
    }

    #[async_test]
    async fn ignores_expired_poll_event() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration); // expired !

        // Prepare the message verifier
        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event(
                participants(5, Some(worker.clone())),
                100,
                "solana".parse().unwrap(),
            ),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            rx,
        );

        let handler_result = handler.handle(&event).await.unwrap();
        assert!(handler_result.is_empty());
        assert_eq!(
            None,
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
    }

    fn get_event(event: impl Into<cosmwasm_std::Event>, contract_address: &TMAddress) -> Event {
        let mut event: cosmwasm_std::Event = event.into();

        event.ty = format!("wasm-{}", event.ty);
        event = event.add_attribute("_contract_address", contract_address.to_string());

        abci::Event::new(
            event.ty,
            event
                .attributes
                .into_iter()
                .map(|cosmwasm_std::Attribute { key, value }| {
                    (STANDARD.encode(key), STANDARD.encode(value))
                }),
        )
        .try_into()
        .unwrap()
    }

    fn get_poll_started_event(
        participants: Vec<TMAddress>,
        expires_at: u64,
        source_chain: ChainName,
    ) -> PollStarted {
        let signature_1 = "3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP";
        let event_idx_1 = 10_u32;
        let message_id_1 = format!("{signature_1}-{event_idx_1}");

        let signature_2 = "41SgBTfsWbkdixDdVNESM6YmDAzEcKEubGPkaXmtTVUd2EhMaqPEy3qh5ReTtTb4Le4F16SSBFjQCxkekamNrFNT";
        let event_idx_2 = 88_u32;
        let message_id_2 = format!("{signature_2}-{event_idx_2}");

        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain,
                source_gateway_address: "sol".to_string().parse().unwrap(),
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
                    tx_id: signature_1.parse().unwrap(),
                    event_index: event_idx_1,
                    source_address: "sol".to_string().parse().unwrap(),
                    message_id: message_id_1.parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                    payload_hash: Hash::random().to_fixed_bytes(),
                },
                TxEventConfirmation {
                    tx_id: signature_2.parse().unwrap(),
                    event_index: event_idx_2,
                    source_address: "sol".to_string().parse().unwrap(),
                    message_id: message_id_2.parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                    payload_hash: Hash::random().to_fixed_bytes(),
                },
            ],
        }
    }

    fn get_poll_started_event_with_duplicates(
        participants: Vec<TMAddress>,
        expires_at: u64,
    ) -> PollStarted {
        let signature_1 = "3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP";
        let event_idx_1 = 10_u32;
        let message_id_1 = format!("{signature_1}-{event_idx_1}");
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "solana".parse().unwrap(),
                source_gateway_address: "sol".to_string().parse().unwrap(),
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
                    tx_id: signature_1.parse().unwrap(),
                    event_index: event_idx_1,
                    source_address: "sol".to_string().parse().unwrap(),
                    message_id: message_id_1.parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                    payload_hash: Hash::random().to_fixed_bytes(),
                },
                TxEventConfirmation {
                    tx_id: signature_1.parse().unwrap(),
                    event_index: event_idx_1,
                    source_address: "sol".to_string().parse().unwrap(),
                    message_id: message_id_1.parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                    payload_hash: Hash::random().to_fixed_bytes(),
                },
            ],
        }
    }

    fn participants(n: u8, worker: Option<TMAddress>) -> Vec<TMAddress> {
        (0..n)
            .map(|_| TMAddress::random(PREFIX))
            .chain(worker)
            .collect()
    }
}

use async_trait::async_trait;
use connection_router::state::ChainName;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
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
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::solana::msg_verifier::verify_message;
use crate::solana::rpc::RpcCacheWrapper;
use crate::types::TMAddress;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug, PartialEq)]
pub struct Message {
    pub tx_id: String,
    pub event_index: u64,
    pub destination_address: String,
    pub destination_chain: connection_router::state::ChainName,
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

pub struct Handler<B>
where
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: RpcCacheWrapper,
    chain: ChainName,
    broadcast_client: B,
    latest_block_height: Receiver<u64>,
}

impl<B> Handler<B>
where
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: RpcCacheWrapper,
        chain: ChainName,
        broadcast_client: B,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            rpc_client,
            chain,
            broadcast_client,
            latest_block_height,
        }
    }
    async fn broadcast_votes(&self, poll_id: PollId, votes: Vec<Vote>) -> Result<()> {
        let msg = serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes })
            .expect("vote msg should serialize");
        let tx = MsgExecuteContract {
            sender: self.worker.as_ref().clone(),
            contract: self.voting_verifier.as_ref().clone(),
            msg,
            funds: vec![],
        };

        self.broadcast_client
            .broadcast(tx)
            .await
            .change_context(Error::Broadcaster)
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
        Ok(verify_message(source_gateway_address, sol_tx, &msg))
    }
}

#[async_trait]
impl<B> EventHandler for Handler<B>
where
    B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<()> {
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
                return Ok(());
            }
            event => event.change_context(Error::DeserializeEvent)?,
        };

        if self.chain != source_chain {
            return Ok(());
        }

        if self.voting_verifier != contract_address {
            return Ok(());
        }

        if !participants.contains(&self.worker) {
            return Ok(());
        }

        let latest_block_height = *self.latest_block_height.borrow();
        if latest_block_height >= expires_at {
            info!(poll_id = poll_id.to_string(), "skipping expired poll");
            return Ok(());
        }

        let mut votes: Vec<Vote> = Vec::new();

        for msg in messages {
            votes.push(self.process_message(&msg, &source_gateway_address).await?);
        }

        self.broadcast_votes(poll_id, votes).await
    }
}

#[cfg(test)]
mod test {

    use std::num::NonZeroUsize;

    use axelar_wasm_std::nonempty;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use events::Event;
    use solana_client::rpc_request::RpcRequest;
    use tendermint::abci;
    use tokio::sync::watch;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use crate::{
        queue::queued_broadcaster::MockBroadcasterClient,
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
        let source_chain = ChainName::from_str("solana").unwrap();

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .once()
            .returning(|_| Ok(()));

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event(
                participants(5, Some(worker.clone())),
                100,
                source_chain.clone(),
            ),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            source_chain,
            broadcast_client,
            rx,
        );

        handler.handle(&event).await.unwrap();
        assert_eq!(
            Some(&2),
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
    }

    #[async_test]
    async fn ignores_events_from_other_chains() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);
        let source_chain = ChainName::from_str("solana").unwrap();
        let poll_started_source_chain = ChainName::from_str("other_chain").unwrap(); // A different, unexpected source chain.

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .never();

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event(
                participants(5, Some(worker.clone())),
                100,
                poll_started_source_chain,
            ),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            source_chain,
            broadcast_client,
            rx,
        );

        handler.handle(&event).await.unwrap();

        assert_eq!(
            None,
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
        let source_chain = ChainName::from_str("solana").unwrap();

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .once()
            .returning(|_| Ok(()));

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event_with_duplicates(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            source_chain,
            broadcast_client,
            rx,
        );

        handler.handle(&event).await.unwrap();

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
        let source_chain = ChainName::from_str("solana").unwrap();

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .never();

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event(
                participants(5, Some(worker.clone())),
                100,
                source_chain.clone(),
            ),
            &TMAddress::random(PREFIX), // A different, unexpected address comes from the event.
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            source_chain,
            broadcast_client,
            rx,
        );

        handler.handle(&event).await.unwrap();

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
        let source_chain = ChainName::from_str("solana").unwrap();

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .never();

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event(participants(5, None), 100, source_chain.clone()), // This worker is not in participant set. So will skip the event.
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            source_chain,
            broadcast_client,
            rx,
        );

        handler.handle(&event).await.unwrap();

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
        let source_chain = ChainName::from_str("solana").unwrap();

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .never();

        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();

        let event: Event = get_event(
            get_poll_started_event(
                participants(5, Some(worker.clone())),
                100,
                source_chain.clone(),
            ),
            &voting_verifier,
        );

        let handler = super::Handler::new(
            worker,
            voting_verifier,
            RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(10).unwrap()),
            source_chain,
            broadcast_client,
            rx,
        );

        handler.handle(&event).await.unwrap();

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
        get_poll_started_event_with_source_chain(participants, expires_at, source_chain)
    }

    fn get_poll_started_event_with_source_chain(
        participants: Vec<TMAddress>,
        expires_at: u64,
        source_chain: ChainName,
    ) -> PollStarted {
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
            messages: vec![
                TxEventConfirmation {
                    tx_id: nonempty::String::from_str("3GLo4z4siudHxW1BMHBbkTKy7kfbssNFaxLR5hTjhEXCUzp2Pi2VVwybc1s96pEKjRre7CcKKeLhni79zWTNUseP").unwrap(),
                    event_index: 10,
                    source_address: "sol".to_string().parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                    payload_hash: Hash::random().to_fixed_bytes(),
                },
                TxEventConfirmation {
                    tx_id: nonempty::String::from_str("41SgBTfsWbkdixDdVNESM6YmDAzEcKEubGPkaXmtTVUd2EhMaqPEy3qh5ReTtTb4Le4F16SSBFjQCxkekamNrFNT").unwrap(),
                    event_index: 11,
                    source_address: "sol".to_string().parse().unwrap(),
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
        let tx_id = nonempty::String::from_str("41SgBTfsWbkdixDdVNESM6YmDAzEcKEubGPkaXmtTVUd2EhMaqPEy3qh5ReTtTb4Le4F16SSBFjQCxkekamNrFNT").unwrap();
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
            messages: vec![
                TxEventConfirmation {
                    tx_id: tx_id.clone(),
                    event_index: 10,
                    source_address: "sol".to_string().parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                    payload_hash: Hash::random().to_fixed_bytes(),
                },
                TxEventConfirmation {
                    tx_id,
                    event_index: 10,
                    source_address: "sol".to_string().parse().unwrap(),
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

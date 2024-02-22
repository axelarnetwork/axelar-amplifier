use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use serde::Deserialize;
use solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta;
use std::collections::HashSet;
use std::convert::TryInto;
use tracing::info;

use axelar_wasm_std::voting::{PollId, Vote};
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use tokio::sync::watch::Receiver;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::solana::{json_rpc::SolanaClient, verifier::verify_message};
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
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
    expires_at: u64,
}

pub struct Handler<C, B>
where
    C: SolanaClient + Send + Sync,
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    rpc_client: C,
    broadcast_client: B,
    latest_block_height: Receiver<u64>,
}

impl<C, B> Handler<C, B>
where
    C: SolanaClient + Send + Sync,
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: C,
        broadcast_client: B,
        latest_block_height: Receiver<u64>,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            rpc_client,
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
}

#[async_trait]
impl<C, B> EventHandler for Handler<C, B>
where
    C: SolanaClient + Send + Sync,
    B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &Event) -> Result<()> {
        let PollStartedEvent {
            contract_address,
            poll_id,
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

        let tx_ids_from_msg: HashSet<_> = messages.iter().map(|msg| msg.tx_id.clone()).collect();

        let mut sol_txs: Vec<EncodedConfirmedTransactionWithStatusMeta> = Vec::new();
        for msg_tx in tx_ids_from_msg {
            let sol_tx = self.rpc_client.get_transaction(msg_tx).await.map_err(|_|Error::TxReceipts)?;
            sol_txs.push(sol_tx);
        }

        let mut votes: Vec<Vote> = vec![Vote::NotFound; messages.len()];
        for msg in messages {
            votes = sol_txs
                .iter()
                .map(|tx| verify_message(&source_gateway_address, tx, &msg))
                .collect();
        }

        self.broadcast_votes(poll_id, votes).await
    }
}

#[cfg(test)]
mod test {

    use axelar_wasm_std::nonempty;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use events::Event;
    use tendermint::abci;
    use tokio::sync::watch;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use crate::{
        queue::queued_broadcaster::MockBroadcasterClient,
        solana::json_rpc::MockSolanaClient,
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

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .once()
            .returning(|_| Ok(()));
        let mut sol_client = MockSolanaClient::new();
        sol_client
            .expect_get_transaction()
            .times(2)
            .returning(|_| Ok(dummy_tx_type()));

        let event: Event = get_event(
            get_poll_started_event(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let handler =
            super::Handler::new(worker, voting_verifier, sol_client, broadcast_client, rx);

        handler.handle(&event).await.unwrap();
    }

    #[async_test]
    async fn must_skip_duplicated_tx() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .once()
            .returning(|_| Ok(()));
        let mut sol_client = MockSolanaClient::new();
        sol_client
            .expect_get_transaction()
            .once() // Only the first msg is verified, skipping the duplicated one.
            .returning(|_| Ok(dummy_tx_type()));

        let event: Event = get_event(
            get_poll_started_event_with_duplicates(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let handler =
            super::Handler::new(worker, voting_verifier, sol_client, broadcast_client, rx);

        handler.handle(&event).await.unwrap();
    }

    fn dummy_tx_type() -> EncodedConfirmedTransactionWithStatusMeta {
        // Example from https://solana.com/docs/rpc/http/gettransaction
        serde_json::from_str(include_str!("../solana/tests/solana_tx.json")).unwrap()
    }

    #[async_test]
    async fn ignores_poll_event_if_voting_verifier_address_not_match_event_address() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .never();

        let mut sol_client = MockSolanaClient::new();
        sol_client.expect_get_transaction().never();

        let event: Event = get_event(
            get_poll_started_event(participants(5, Some(worker.clone())), 100),
            &TMAddress::random(PREFIX), // A different, unexpected address comes from the event.
        );

        let handler =
            super::Handler::new(worker, voting_verifier, sol_client, broadcast_client, rx);

        handler.handle(&event).await.unwrap();
    }

    #[async_test]
    async fn ignores_poll_event_if_worker_not_part_of_participants() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration - 1);

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .never();

        let mut sol_client = MockSolanaClient::new();
        sol_client.expect_get_transaction().never();

        let event: Event = get_event(
            get_poll_started_event(participants(5, None), 100), // This worker is not in participant set. So will skip the event.
            &voting_verifier,
        );

        let handler =
            super::Handler::new(worker, voting_verifier, sol_client, broadcast_client, rx);

        handler.handle(&event).await.unwrap();
    }

    #[async_test]
    async fn ignores_expired_poll_event() {
        // Setup the context
        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let expiration = 100u64;
        let (_, rx) = watch::channel(expiration); // expired !

        // Prepare the message verifier and the vote broadcaster
        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast::<MsgExecuteContract>()
            .never();

        let mut sol_client = MockSolanaClient::new();
        sol_client.expect_get_transaction().never();

        let event: Event = get_event(
            get_poll_started_event(participants(5, Some(worker.clone())), 100),
            &voting_verifier,
        );

        let handler =
            super::Handler::new(worker, voting_verifier, sol_client, broadcast_client, rx);

        handler.handle(&event).await.unwrap();
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

    fn get_poll_started_event(participants: Vec<TMAddress>, expires_at: u64) -> PollStarted {
        get_poll_started_event_with_source_chain(participants, expires_at, "starknet")
    }

    fn get_poll_started_event_with_source_chain(
        participants: Vec<TMAddress>,
        expires_at: u64,
        source_chain: &str,
    ) -> PollStarted {
        PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: source_chain.parse().unwrap(),
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
                    tx_id: format!("0x{:x}", Hash::random()).parse().unwrap(),
                    event_index: 10,
                    source_address: "sol".to_string().parse().unwrap(),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                    payload_hash: Hash::random().to_fixed_bytes(),
                },
                TxEventConfirmation {
                    tx_id: format!("0x{:x}", Hash::random()).parse().unwrap(),
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
        let tx_id: nonempty::String = format!("0x{:x}", Hash::random()).parse().unwrap();
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

use std::collections::HashSet;
use std::convert::TryInto;

use async_trait::async_trait;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::ResultExt;
use serde::Deserialize;

use axelar_wasm_std::voting::PollID;
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;
use voting_verifier::msg::ExecuteMsg;

use crate::event_processor::EventHandler;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::types::{Hash, TMAddress};

use crate::mvx::proxy::MvxProxy;
use crate::mvx::verifier::verify_message;
use multiversx_sdk::data::address::Address;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub tx_id: String,
    pub event_index: usize,
    pub destination_address: String,
    pub destination_chain: connection_router::state::ChainName,
    pub source_address: Address,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollID,
    source_gateway_address: Address,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

pub struct Handler<P, B>
where
    P: MvxProxy + Send + Sync,
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    blockchain: P,
    broadcast_client: B,
}

impl<P, B> Handler<P, B>
where
    P: MvxProxy + Send + Sync,
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        blockchain: P,
        broadcast_client: B,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
            blockchain,
            broadcast_client,
        }
    }

    async fn broadcast_votes(&self, poll_id: PollID, votes: Vec<bool>) -> Result<()> {
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
impl<P, B> EventHandler for Handler<P, B>
where
    P: MvxProxy + Send + Sync,
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

        let tx_hashes: HashSet<_> = messages
            .iter()
            .map(|message| message.tx_id.clone())
            .collect();
        let transactions_info = self
            .blockchain
            .transactions_info_with_results(tx_hashes)
            .await
            .change_context(Error::TxReceipts)?;

        let votes = messages
            .iter()
            .map(|msg| {
                transactions_info
                    .get(&msg.tx_id)
                    .map_or(false, |transaction| {
                        verify_message(&source_gateway_address, transaction, msg)
                    })
            })
            .collect();

        self.broadcast_votes(poll_id, votes).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::TryInto;

    use crate::handlers::errors::Error;
    use crate::mvx::proxy::MockMvxProxy;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmwasm_std;
    use error_stack::{Report, Result};
    use tendermint::abci;
    use tokio::test as async_test;

    use events::Event;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::queue::queued_broadcaster;
    use crate::types::{EVMAddress, Hash, TMAddress};

    use crate::queue::queued_broadcaster::MockBroadcasterClient;

    const PREFIX: &str = "axelar";

    #[test]
    fn should_deserialize_poll_started_event() {
        let event: Result<PollStartedEvent, events::Error> = get_event(
            poll_started_event(participants(5, None)),
            &TMAddress::random(PREFIX),
        )
        .try_into();

        assert!(event.is_ok());

        let event = event.unwrap();

        assert!(event.poll_id == 100u64.into());
        assert!(
            event.source_gateway_address.to_bech32_string().unwrap()
                == "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx"
        );

        let message = event.messages.get(0).unwrap();

        assert!(
            message.tx_id == "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312"
        );
        assert!(message.event_index == 1usize);
        assert!(message.destination_chain.to_string() == "ethereum");
        assert!(
            message.source_address.to_bech32_string().unwrap()
                == "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7"
        );
    }

    // Should not handle event if it is not a poll started event
    #[async_test]
    async fn not_poll_started_event() {
        let event = get_event(
            cosmwasm_std::Event::new("transfer"),
            &TMAddress::random(PREFIX),
        );

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            MockMvxProxy::new(),
            MockBroadcasterClient::new(),
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if it is not emitted from voting verifier
    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = get_event(
            poll_started_event(participants(5, None)),
            &TMAddress::random(PREFIX),
        );

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            MockMvxProxy::new(),
            MockBroadcasterClient::new(),
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    // Should not handle event if worker is not a poll participant
    #[async_test]
    async fn worker_is_not_a_participant() {
        let voting_verifier = TMAddress::random(PREFIX);
        let event = get_event(poll_started_event(participants(5, None)), &voting_verifier);

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            voting_verifier,
            MockMvxProxy::new(),
            MockBroadcasterClient::new(),
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    #[async_test]
    async fn failed_to_get_transactions_info_with_results() {
        let mut proxy = MockMvxProxy::new();
        proxy
            .expect_transactions_info_with_results()
            .returning(|_| Err(Report::from(Error::DeserializeEvent)));

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);

        let event = get_event(
            poll_started_event(participants(5, Some(worker.clone()))),
            &voting_verifier,
        );

        let handler =
            super::Handler::new(worker, voting_verifier, proxy, MockBroadcasterClient::new());

        assert!(matches!(
            *handler.handle(&event).await.unwrap_err().current_context(),
            Error::TxReceipts
        ));
    }

    #[async_test]
    async fn failed_to_broadcast() {
        let mut proxy = MockMvxProxy::new();
        proxy
            .expect_transactions_info_with_results()
            .returning(|_| Ok(HashMap::new()));

        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast()
            .returning(move |_: MsgExecuteContract| {
                Err(Report::from(queued_broadcaster::Error::Broadcast))
            });

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::random(PREFIX);
        let event = get_event(
            poll_started_event(participants(5, Some(worker.clone()))),
            &voting_verifier,
        );

        let handler = super::Handler::new(worker, voting_verifier, proxy, broadcast_client);

        assert!(matches!(
            *handler.handle(&event).await.unwrap_err().current_context(),
            Error::Broadcaster
        ));
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
            messages: vec![TxEventConfirmation {
                tx_id: "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312"
                    .parse()
                    .unwrap(),
                event_index: 1,
                source_address: "erd1qqqqqqqqqqqqqpgqzqvm5ywqqf524efwrhr039tjs29w0qltkklsa05pk7"
                    .parse()
                    .unwrap(),
                destination_chain: "ethereum".parse().unwrap(),
                destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                payload_hash: Hash::random().to_fixed_bytes(),
            }],
        }
    }

    fn participants(n: u8, worker: Option<TMAddress>) -> Vec<TMAddress> {
        (0..n)
            .into_iter()
            .map(|_| TMAddress::random(PREFIX))
            .chain(worker.into_iter())
            .collect()
    }
}

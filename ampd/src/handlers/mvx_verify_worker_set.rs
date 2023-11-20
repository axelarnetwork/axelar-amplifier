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
use crate::types::TMAddress;

use crate::mvx::proxy::MvxProxy;
use crate::mvx::verifier::verify_worker_set;
use multiversx_sdk::data::address::Address;

use connection_router::state::ID_SEPARATOR;
use cosmwasm_std::{HexBinary, Uint256};
use tracing::{info, info_span};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Operators {
    pub weights_by_addresses: Vec<(HexBinary, Uint256)>,
    pub threshold: Uint256,
}

#[derive(Deserialize, Debug)]
pub struct WorkerSetConfirmation {
    pub tx_id: String,
    pub event_index: usize,
    pub operators: Operators,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-worker_set_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    worker_set: WorkerSetConfirmation,
    poll_id: PollID,
    source_gateway_address: Address,
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

    async fn broadcast_vote(&self, poll_id: PollID, vote: bool) -> Result<()> {
        let msg = serde_json::to_vec(&ExecuteMsg::Vote {
            poll_id,
            votes: vec![vote],
        })
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
            participants,
            worker_set,
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

        let transaction_info = self
            .blockchain
            .transaction_info_with_results(&worker_set.tx_id)
            .await
            .change_context(Error::TxReceipts)?;

        let vote = info_span!(
            "verify a new worker set for MultiversX chain",
            poll_id = poll_id.to_string(),
            id = format!(
                "{}{}{}",
                worker_set.tx_id, ID_SEPARATOR, worker_set.event_index
            )
        )
        .in_scope(|| {
            info!("ready to verify a new worker set in poll");

            let vote = transaction_info.map_or(false, |transaction| {
                verify_worker_set(&source_gateway_address, &transaction, &worker_set)
            });
            info!(vote, "ready to vote for a new worker set in poll");

            vote
        });

        self.broadcast_vote(poll_id, vote).await
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use crate::handlers::errors::Error;
    use crate::mvx::proxy::MockMvxProxy;
    use axelar_wasm_std::operators::Operators;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmrs::cosmwasm::MsgExecuteContract;
    use cosmwasm_std;
    use cosmwasm_std::{HexBinary, Uint256};
    use error_stack::{Report, Result};
    use tendermint::abci;
    use tokio::test as async_test;

    use events::Event;
    use voting_verifier::events::{
        PollMetadata, PollStarted, WorkerSetConfirmation,
    };

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::queue::queued_broadcaster;
    use crate::types::{TMAddress};
    use cosmrs::AccountId;
    use std::str::FromStr;

    use crate::queue::queued_broadcaster::MockBroadcasterClient;

    const PREFIX: &str = "axelar";

    #[test]
    fn should_deserialize_poll_started_event() {
        let event: Result<PollStartedEvent, events::Error> =
            get_event(poll_started_event(), &TMAddress::random(PREFIX)).try_into();

        assert!(event.is_ok());

        let event = event.unwrap();

        assert!(event.poll_id == 100u64.into());
        assert!(
            event.source_gateway_address.to_bech32_string().unwrap()
                == "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx"
        );

        let worker_set = event.worker_set;

        assert!(
            worker_set.tx_id == "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312"
        );
        assert!(worker_set.event_index == 1usize);
        assert!(worker_set.operators.weights_by_addresses.len() == 2);
        assert!(worker_set.operators.threshold == Uint256::from(20u128));

        let operator1 = worker_set.operators.weights_by_addresses.get(0).unwrap();
        let operator2 = worker_set.operators.weights_by_addresses.get(1).unwrap();

        assert!(
            operator1.0
                == HexBinary::from_hex(
                    "ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b6",
                )
                .unwrap()
        );
        assert!(operator1.1 == Uint256::from(10u128));

        assert!(
            operator2.0
                == HexBinary::from_hex(
                    "ef637606f3144ee46343ba4a25c261b5c400ade88528e876f3deababa22a4449",
                )
                .unwrap()
        );
        assert!(operator2.1 == Uint256::from(10u128));
    }

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

    #[async_test]
    async fn contract_is_not_voting_verifier() {
        let event = get_event(poll_started_event(), &TMAddress::random(PREFIX));

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            MockMvxProxy::new(),
            MockBroadcasterClient::new(),
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    #[async_test]
    async fn worker_is_not_a_participant() {
        let voting_verifier = TMAddress::random(PREFIX);
        let event = get_event(poll_started_event(), &voting_verifier);

        let handler = super::Handler::new(
            TMAddress::random(PREFIX),
            voting_verifier,
            MockMvxProxy::new(),
            MockBroadcasterClient::new(),
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    #[async_test]
    async fn failed_to_get_transaction_info_with_results() {
        let mut proxy = MockMvxProxy::new();
        proxy
            .expect_transaction_info_with_results()
            .returning(|_| Err(Report::from(Error::DeserializeEvent)));

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::from(
            AccountId::from_str("axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7").unwrap(),
        );

        let event = get_event(poll_started_event(), &voting_verifier);

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
            .expect_transaction_info_with_results()
            .returning(|_| Ok(None));

        let mut broadcast_client = MockBroadcasterClient::new();
        broadcast_client
            .expect_broadcast()
            .returning(move |_: MsgExecuteContract| {
                Err(Report::from(queued_broadcaster::Error::Broadcast))
            });

        let voting_verifier = TMAddress::random(PREFIX);
        let worker = TMAddress::from(
            AccountId::from_str("axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7").unwrap(),
        );
        let event = get_event(
            poll_started_event(),
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

    fn poll_started_event() -> PollStarted {
        PollStarted::WorkerSet {
            worker_set: WorkerSetConfirmation {
                tx_id: "dfaf64de66510723f2efbacd7ead3c4f8c856aed1afc2cb30254552aeda47312"
                    .parse()
                    .unwrap(),
                event_index: 1,
                operators: Operators {
                    threshold: 20u64.into(),
                    weights_by_addresses: vec![
                        (
                            HexBinary::from_hex(
                                "ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b6",
                            )
                            .unwrap(),
                            Uint256::from(10u128),
                        ),
                        (
                            HexBinary::from_hex(
                                "ef637606f3144ee46343ba4a25c261b5c400ade88528e876f3deababa22a4449",
                            )
                            .unwrap(),
                            Uint256::from(10u128),
                        ),
                    ],
                },
            },
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "multiversx".parse().unwrap(),
                source_gateway_address:
                    "erd1qqqqqqqqqqqqqpgqsvzyz88e8v8j6x3wquatxuztnxjwnw92kkls6rdtzx"
                        .parse()
                        .unwrap(),
                confirmation_height: 15,
                expires_at: 100,
                participants: vec![
                    cosmwasm_std::Addr::unchecked(
                        "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7",
                    ),
                    cosmwasm_std::Addr::unchecked(
                        "axelarvaloper1tee73c83k2vqky9gt59jd3ztwxhqjm27l588q6",
                    ),
                    cosmwasm_std::Addr::unchecked(
                        "axelarvaloper1ds9z59d9szmxlzt6f8f6l6sgaenxdyd6095gcg",
                    ),
                ],
            },
        }
    }
}

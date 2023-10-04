use std::collections::HashMap;
use std::convert::TryInto;

use async_trait::async_trait;
use error_stack::ResultExt;
use serde::Deserialize;
use sui_json_rpc_types::SuiTransactionBlockResponse;
use sui_types::base_types::{SuiAddress, TransactionDigest};

use axelar_wasm_std::voting::PollID;
use events::{Error::EventTypeMismatch, Event};
use events_derive::try_from;

use crate::event_processor::EventHandler;
use crate::handlers::{errors::Error, voter::Voter};
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::sui::{json_rpc::SuiClient, verifier::verify_message};
use crate::types::{Hash, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub tx_id: TransactionDigest,
    pub event_index: u64,
    pub destination_address: String,
    pub destination_chain: connection_router::state::ChainName,
    pub source_address: SuiAddress,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
#[try_from("wasm-messages_poll_started")]
struct PollStartedEvent {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    poll_id: PollID,
    source_gateway_address: SuiAddress,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

pub struct Handler<C, B>
where
    C: SuiClient + Send + Sync,
    B: BroadcasterClient,
{
    voter: Voter<B>,
    rpc_client: C,
}

impl<C, B> Handler<C, B>
where
    C: SuiClient + Send + Sync,
    B: BroadcasterClient,
{
    #[allow(dead_code)]
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        rpc_client: C,
        broadcast_client: B,
    ) -> Self {
        Self {
            rpc_client,
            voter: Voter::new(worker, voting_verifier, broadcast_client),
        }
    }

    async fn transaction_blocks(
        &self,
        digests: Vec<TransactionDigest>,
    ) -> Result<HashMap<TransactionDigest, SuiTransactionBlockResponse>> {
        Ok(self
            .rpc_client
            .transaction_blocks(digests)
            .await
            .change_context(Error::TxReceipts)?
            .into_iter()
            .map(|tx_block| (tx_block.digest, tx_block))
            .collect())
    }
}

#[async_trait]
impl<C, B> EventHandler for Handler<C, B>
where
    C: SuiClient + Send + Sync,
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

        if self.voter.voting_verifier() != &contract_address {
            return Ok(());
        }

        if !participants.contains(self.voter.worker()) {
            return Ok(());
        }

        let transaction_blocks = self
            .transaction_blocks(messages.iter().map(|message| message.tx_id).collect())
            .await?;

        let votes = messages
            .iter()
            .map(|msg| {
                transaction_blocks
                    .get(&msg.tx_id)
                    .map_or(false, |tx_block| {
                        verify_message(&source_gateway_address, tx_block, msg)
                    })
            })
            .collect();

        self.voter.vote(poll_id, votes).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::TryInto;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmrs::{cosmwasm::MsgExecuteContract, AccountId};
    use cosmwasm_std;
    use cosmwasm_std::HexBinary;
    use error_stack::{Report, Result};
    use ethers::providers::ProviderError;
    use sui_json_rpc_types::SuiTransactionBlockResponse;
    use sui_types::base_types::{SuiAddress, TransactionDigest};
    use tendermint::abci;
    use tokio::test as async_test;

    use events::Event;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::PollStartedEvent;
    use crate::event_processor::EventHandler;
    use crate::handlers::errors::Error;
    use crate::queue::queued_broadcaster::MockBroadcasterClient;
    use crate::sui::json_rpc::MockSuiClient;
    use crate::types::{EVMAddress, Hash, TMAddress};

    #[test]
    fn should_deserialize_correct_event() {
        let event: Result<PollStartedEvent, events::Error> = (&get_poll_started_event()).try_into();

        assert!(event.is_ok());
    }

    #[async_test]
    async fn failed_to_get_tx_blocks() {
        let mut sui_client = MockSuiClient::new();
        sui_client.expect_transaction_blocks().returning(|_| {
            Err(Report::from(ProviderError::CustomError(
                "failed to get tx blocks".to_string(),
            )))
        });

        let handler = super::Handler::new(
            TMAddress::random(),
            TMAddress::random(),
            sui_client,
            MockBroadcasterClient::new(),
        );

        assert!(matches!(
            *handler
                .transaction_blocks(vec![TransactionDigest::random()])
                .await
                .unwrap_err()
                .current_context(),
            Error::TxReceipts
        ));
    }

    #[async_test]
    async fn should_get_tx_blocks() {
        let handler = super::Handler::new(
            TMAddress::random(),
            TMAddress::random(),
            mock_sui_client(),
            MockBroadcasterClient::new(),
        );

        let digests: Vec<_> = (0..10).map(|_| TransactionDigest::random()).collect();
        let expected: HashMap<_, _> = digests
            .clone()
            .into_iter()
            .map(|digest| {
                let mut res = SuiTransactionBlockResponse::default();
                res.digest = digest.clone();
                (digest, res)
            })
            .collect();

        assert_eq!(handler.transaction_blocks(digests).await.unwrap(), expected);
    }

    // should not handle event if it is not a poll started event
    #[async_test]
    async fn not_poll_started_event() {
        let handler = super::Handler::new(
            TMAddress::random(),
            TMAddress::random(),
            MockSuiClient::new(),
            MockBroadcasterClient::new(),
        );

        let mut event: Event = get_poll_started_event();
        match event {
            Event::Abci {
                ref mut event_type, ..
            } => {
                *event_type = "some other event".into();
            }
            _ => panic!("incorrect event type"),
        }
        assert!(handler.handle(&event).await.is_ok());
    }

    // should not handle event if voting verifier address does not match
    #[async_test]
    async fn contract_address_mismatch() {
        let handler = super::Handler::new(
            TMAddress::random(),
            TMAddress::random(),
            MockSuiClient::new(),
            MockBroadcasterClient::new(),
        );

        assert!(handler.handle(&get_poll_started_event()).await.is_ok());
    }

    // should not handle event if worker is not a participant
    #[async_test]
    async fn not_a_participant() {
        let event = get_poll_started_event();
        let contract_address = match event {
            Event::Abci { ref attributes, .. } => attributes["_contract_address"].as_str().unwrap(),
            _ => panic!("incorrect event type"),
        };

        let handler = super::Handler::new(
            TMAddress::random(),
            contract_address.parse::<AccountId>().unwrap().into(),
            MockSuiClient::new(),
            MockBroadcasterClient::new(),
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    #[async_test]
    async fn should_vote() {
        let event = get_poll_started_event();
        let (contract, worker) = match event {
            Event::Abci { ref attributes, .. } => (
                attributes["_contract_address"].as_str().unwrap(),
                attributes["participants"].as_array().unwrap()[0]
                    .as_str()
                    .unwrap(),
            ),
            _ => panic!("incorrect event type"),
        };

        let mut voter = MockBroadcasterClient::new();
        voter
            .expect_broadcast()
            .once()
            .returning(move |_: MsgExecuteContract| Ok(()));

        let handler = super::Handler::new(
            worker.parse::<AccountId>().unwrap().into(),
            contract.parse::<AccountId>().unwrap().into(),
            mock_sui_client(),
            voter,
        );

        assert!(handler.handle(&event).await.is_ok());
    }

    fn get_poll_started_event() -> Event {
        let poll_started = PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "sui".parse().unwrap(),
                source_gateway_address: SuiAddress::random_for_testing_only()
                    .to_string()
                    .parse()
                    .unwrap(),
                confirmation_height: 15,
                expires_at: 100,
                participants: vec![
                    cosmwasm_std::Addr::unchecked(TMAddress::random().to_string()),
                    cosmwasm_std::Addr::unchecked(TMAddress::random().to_string()),
                    cosmwasm_std::Addr::unchecked(TMAddress::random().to_string()),
                ],
            },
            messages: vec![TxEventConfirmation {
                tx_id: TransactionDigest::random().to_string().parse().unwrap(),
                event_index: 0,
                source_address: SuiAddress::random_for_testing_only()
                    .to_string()
                    .parse()
                    .unwrap(),
                destination_chain: "ethereum".parse().unwrap(),
                destination_address: format!("0x{:x}", EVMAddress::random()).parse().unwrap(),
                payload_hash: HexBinary::from(Hash::random().as_bytes()),
            }],
        };
        let mut event: cosmwasm_std::Event = poll_started.into();
        event.ty = format!("wasm-{}", event.ty);
        event = event.add_attribute("_contract_address", TMAddress::random().to_string());

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

    fn mock_sui_client() -> MockSuiClient {
        let mut sui_client = MockSuiClient::new();
        sui_client.expect_transaction_blocks().returning(|digests| {
            Ok(digests
                .into_iter()
                .map(|digest| {
                    let mut res = SuiTransactionBlockResponse::default();
                    res.digest = digest;
                    res
                })
                .collect())
        });

        sui_client
    }
}

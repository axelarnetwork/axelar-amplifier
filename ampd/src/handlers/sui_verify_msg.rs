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
    use std::convert::TryInto;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cosmwasm_std;
    use cosmwasm_std::HexBinary;
    use error_stack::Result;
    use sui_types::base_types::{SuiAddress, TransactionDigest};
    use tendermint::abci;

    use crate::types::EVMAddress;
    use events::Event;
    use voting_verifier::events::{PollMetadata, PollStarted, TxEventConfirmation};

    use super::PollStartedEvent;

    #[test]
    fn should_deserialize_correct_event() {
        let event: Result<PollStartedEvent, events::Error> = (&get_poll_started_event()).try_into();

        assert!(event.is_ok());
    }

    fn get_poll_started_event() -> Event {
        let poll_started = PollStarted::Messages {
            metadata: PollMetadata {
                poll_id: "100".parse().unwrap(),
                source_chain: "sui".parse().unwrap(),
                source_gateway_address:
                    "0xcb6c2771773d600a126a5a8c95bb3eeefcdf01863f4ad2a7c11bfe489bebeef6"
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
        event = event.add_attribute(
            "_contract_address",
            "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7",
        );

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
}

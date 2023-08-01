use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use axelar_wasm_std::voting::PollID;
use ethers::types::{TransactionReceipt, U64};
use futures::future::join_all;
use serde::de::value::MapDeserializer;
use serde::Deserialize;

use crate::deserializers::from_str;
use crate::event_processor::EventHandler;
use crate::event_sub;
use crate::evm::error::Error;
use crate::evm::json_rpc::EthereumClient;
use crate::evm::message_verifier::verify_message;
use crate::evm::ChainName;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::types::{EVMAddress, Hash, TMAddress};

const EVENT_TYPE: &str = "wasm-poll_started";

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub tx_id: Hash,
    pub log_index: usize,
    pub destination_address: String,
    pub destination_chain: connection_router::types::ChainName,
    pub source_address: EVMAddress,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
struct Event {
    #[allow(dead_code)]
    poll_id: PollID,
    #[serde(deserialize_with = "from_str")]
    source_chain: connection_router::types::ChainName,
    source_gateway_address: EVMAddress,
    confirmation_height: u64,
    messages: Vec<Message>,
    #[allow(dead_code)]
    participants: Vec<TMAddress>,
}

impl From<&event_sub::Event> for Option<Event> {
    fn from(event: &event_sub::Event) -> Self {
        match event {
            event_sub::Event::Abci { event_type, attributes } if event_type.as_str() == EVENT_TYPE => {
                Event::deserialize(MapDeserializer::new(attributes.clone().into_iter())).ok()
            }
            _ => None,
        }
    }
}

pub struct Handler<C, B>
where
    C: EthereumClient,
    B: BroadcasterClient,
{
    chain: ChainName,
    rpc_client: C,
    #[allow(dead_code)]
    broadcast_client: B,
}

impl<C, B> Handler<C, B>
where
    C: EthereumClient + Send + Sync,
    B: BroadcasterClient,
{
    pub fn new(chain: ChainName, rpc_client: C, broadcast_client: B) -> Self {
        Self {
            chain,
            rpc_client,
            broadcast_client,
        }
    }

    async fn finalized_tx_receipts<T>(
        &self,
        tx_hashes: T,
        confirmation_height: u64,
    ) -> Result<HashMap<Hash, TransactionReceipt>>
    where
        T: IntoIterator<Item = Hash>,
    {
        let latest_finalized_block_height = self
            .chain
            .finalizer(&self.rpc_client, confirmation_height)
            .latest_finalized_block_height()
            .await?;

        Ok(join_all(
            tx_hashes
                .into_iter()
                .map(|tx_hash| self.rpc_client.transaction_receipt(tx_hash)),
        )
        .await
        .into_iter()
        .filter_map(std::result::Result::unwrap_or_default)
        .filter_map(|tx_receipt| {
            if tx_receipt
                .block_number
                .unwrap_or(U64::MAX)
                .le(&latest_finalized_block_height)
            {
                Some((tx_receipt.transaction_hash, tx_receipt))
            } else {
                None
            }
        })
        .collect())
    }
}

#[async_trait]
impl<C, B> EventHandler for Handler<C, B>
where
    C: EthereumClient + Send + Sync,
    B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &event_sub::Event) -> Result<()> {
        let Event {
            source_chain,
            source_gateway_address,
            messages,
            confirmation_height,
            ..
        } = match event.into() {
            Some(event) => event,
            None => return Ok(()),
        };

        if self.chain != source_chain {
            return Ok(());
        }

        let tx_hashes: HashSet<_> = messages.iter().map(|message| message.tx_id).collect();
        let finalized_tx_receipts = self.finalized_tx_receipts(tx_hashes, confirmation_height).await?;

        let _votes: Vec<_> = messages
            .iter()
            .map(|msg| {
                finalized_tx_receipts.get(&msg.tx_id).map_or(false, |tx_receipt| {
                    verify_message(&source_gateway_address, tx_receipt, msg)
                })
            })
            .collect();

        todo!()
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std;
    use cosmwasm_std::HexBinary;
    use tendermint::abci;
    use voting_verifier::events::{EvmMessage, PollStarted};

    use super::Event;
    use crate::{
        event_sub,
        types::{EVMAddress, Hash},
    };

    fn get_poll_started_event() -> event_sub::Event {
        let poll_started = PollStarted {
            poll_id: 100.into(),
            source_chain: "ethereum".parse().unwrap(),
            source_gateway_address: "0x4f4495243837681061c4743b74eedf548d5686a5".into(),
            confirmation_height: 15,
            expires_at: 100,
            messages: vec![
                EvmMessage {
                    tx_id: format!("0x{:x}", Hash::random()),
                    log_index: 0,
                    source_address: format!("0x{:x}", EVMAddress::random()),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", EVMAddress::random()),
                    payload_hash: HexBinary::from(Hash::random().as_bytes()),
                },
                EvmMessage {
                    tx_id: format!("0x{:x}", Hash::random()),
                    log_index: 1,
                    source_address: format!("0x{:x}", EVMAddress::random()),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", EVMAddress::random()),
                    payload_hash: HexBinary::from(Hash::random().as_bytes()),
                },
                EvmMessage {
                    tx_id: format!("0x{:x}", Hash::random()),
                    log_index: 10,
                    source_address: format!("0x{:x}", EVMAddress::random()),
                    destination_chain: "ethereum".parse().unwrap(),
                    destination_address: format!("0x{:x}", EVMAddress::random()),
                    payload_hash: HexBinary::from(Hash::random().as_bytes()),
                },
            ],
            participants: vec![
                cosmwasm_std::Addr::unchecked("axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7"),
                cosmwasm_std::Addr::unchecked("axelarvaloper1tee73c83k2vqky9gt59jd3ztwxhqjm27l588q6"),
                cosmwasm_std::Addr::unchecked("axelarvaloper1ds9z59d9szmxlzt6f8f6l6sgaenxdyd6095gcg"),
            ],
        };
        let mut event: cosmwasm_std::Event = poll_started.into();
        event.ty = format!("wasm-{}", event.ty);

        abci::Event::new(
            event.ty,
            event
                .attributes
                .into_iter()
                .map(|cosmwasm_std::Attribute { key, value }| (key, value)),
        )
        .into()
    }

    #[test]
    fn should_not_deserialize_incorrect_event() {
        // incorrect event type
        let mut event: event_sub::Event = get_poll_started_event();
        match event {
            event_sub::Event::Abci { ref mut event_type, .. } => {
                *event_type = "incorrect".into();
            }
            _ => panic!("incorrect event type"),
        }
        let event: Option<Event> = (&event).into();

        assert!(event.is_none());

        // invalid field
        let mut event = get_poll_started_event();
        match event {
            event_sub::Event::Abci { ref mut attributes, .. } => {
                attributes.insert("source_gateway_address".into(), "invalid".into());
            }
            _ => panic!("incorrect event type"),
        }
        let event: Option<Event> = (&event).into();

        assert!(event.is_none());
    }

    #[test]
    fn should_deserialize_correct_event() {
        let event: Option<Event> = (&get_poll_started_event()).into();

        assert!(event.is_some());
    }
}

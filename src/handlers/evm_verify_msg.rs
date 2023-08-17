use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};

use async_trait::async_trait;
use axelar_wasm_std::voting::PollID;
use connection_router::types::ID_SEPARATOR;
use cosmrs::cosmwasm::MsgExecuteContract;
use error_stack::{IntoReport, ResultExt};
use ethers::types::{TransactionReceipt, U64};
use futures::future::join_all;
use serde::de::value::MapDeserializer;
use serde::Deserialize;
use tracing::{info, info_span};
use valuable::Valuable;
use voting_verifier::msg::ExecuteMsg;

use crate::deserializers::from_str;
use crate::event_processor::EventHandler;
use crate::event_sub;
use crate::evm::json_rpc::EthereumClient;
use crate::evm::message_verifier::verify_message;
use crate::evm::ChainName;
use crate::handlers::errors::Error;
use crate::queue::queued_broadcaster::BroadcasterClient;
use crate::types::{EVMAddress, Hash, TMAddress};

const EVENT_TYPE: &str = "wasm-poll_started";

type Result<T> = error_stack::Result<T, Error>;

#[derive(Deserialize, Debug)]
pub struct Message {
    pub tx_id: Hash,
    pub log_index: u64,
    pub destination_address: String,
    pub destination_chain: connection_router::types::ChainName,
    pub source_address: EVMAddress,
    pub payload_hash: Hash,
}

#[derive(Deserialize, Debug)]
struct Event {
    #[serde(rename = "_contract_address")]
    contract_address: TMAddress,
    #[serde(deserialize_with = "from_str")]
    poll_id: PollID,
    #[serde(deserialize_with = "from_str")]
    source_chain: connection_router::types::ChainName,
    source_gateway_address: EVMAddress,
    confirmation_height: u64,
    messages: Vec<Message>,
    participants: Vec<TMAddress>,
}

impl TryFrom<&event_sub::Event> for Option<Event> {
    type Error = Error;

    fn try_from(event: &event_sub::Event) -> std::result::Result<Self, Self::Error> {
        match event {
            event_sub::Event::Abci { event_type, attributes } if event_type.as_str() == EVENT_TYPE => Ok(Some(
                Event::deserialize(MapDeserializer::new(attributes.clone().into_iter()))?,
            )),
            _ => Ok(None),
        }
    }
}

pub struct Handler<C, B>
where
    C: EthereumClient,
    B: BroadcasterClient,
{
    worker: TMAddress,
    voting_verifier: TMAddress,
    chain: ChainName,
    rpc_client: C,
    broadcast_client: B,
}

impl<C, B> Handler<C, B>
where
    C: EthereumClient + Send + Sync,
    B: BroadcasterClient,
{
    pub fn new(
        worker: TMAddress,
        voting_verifier: TMAddress,
        chain: ChainName,
        rpc_client: C,
        broadcast_client: B,
    ) -> Self {
        Self {
            worker,
            voting_verifier,
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
            .await
            .change_context(Error::Finalizer)?;

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

    async fn broadcast_votes(&self, poll_id: PollID, votes: Vec<bool>) -> Result<()> {
        let msg = serde_json::to_vec(&ExecuteMsg::Vote { poll_id, votes }).expect("vote msg should serialize");
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
    C: EthereumClient + Send + Sync,
    B: BroadcasterClient + Send + Sync,
{
    type Err = Error;

    async fn handle(&self, event: &event_sub::Event) -> Result<()> {
        let Event {
            contract_address,
            poll_id,
            source_chain,
            source_gateway_address,
            messages,
            confirmation_height,
            participants,
        } = match event.try_into().into_report()? {
            Some(event) => event,
            None => return Ok(()),
        };

        if self.voting_verifier != contract_address {
            return Ok(());
        }

        if self.chain != source_chain {
            return Ok(());
        }

        if !participants.contains(&self.worker) {
            return Ok(());
        }

        let tx_hashes: HashSet<_> = messages.iter().map(|message| message.tx_id).collect();
        let finalized_tx_receipts = self.finalized_tx_receipts(tx_hashes, confirmation_height).await?;

        let poll_id_str: String = poll_id.into();
        let source_chain_str: String = source_chain.into();
        let message_ids = messages
            .iter()
            .map(|message| format!("0x{:x}{}{}", message.tx_id, ID_SEPARATOR, message.log_index))
            .collect::<Vec<_>>();
        let votes = info_span!(
            "verify messages from an EVM chain",
            poll_id = poll_id_str,
            source_chain = source_chain_str,
            message_ids = message_ids.as_value()
        )
        .in_scope(|| {
            info!("ready to verify messages in poll",);

            let votes: Vec<_> = messages
                .iter()
                .map(|msg| {
                    finalized_tx_receipts.get(&msg.tx_id).map_or(false, |tx_receipt| {
                        verify_message(&source_gateway_address, tx_receipt, msg)
                    })
                })
                .collect();
            info!(votes = votes.as_value(), "ready to vote for messages in poll");

            votes
        });

        self.broadcast_votes(poll_id, votes).await
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
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
            poll_id: "100".parse().unwrap(),
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
        event = event.add_attribute(
            "_contract_address",
            "axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7",
        );

        abci::Event::new(
            event.ty,
            event
                .attributes
                .into_iter()
                .map(|cosmwasm_std::Attribute { key, value }| (STANDARD.encode(key), STANDARD.encode(value))),
        )
        .try_into()
        .unwrap()
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
        let event: Option<Event> = (&event).try_into().unwrap();

        assert!(event.is_none());

        // invalid field
        let mut event = get_poll_started_event();
        match event {
            event_sub::Event::Abci { ref mut attributes, .. } => {
                attributes.insert("source_gateway_address".into(), "invalid".into());
            }
            _ => panic!("incorrect event type"),
        }
        assert!(<&event_sub::Event as TryInto<Option<Event>>>::try_into(&event).is_err());
    }

    #[test]
    fn should_deserialize_correct_event() {
        let event: Option<Event> = (&get_poll_started_event()).try_into().unwrap();

        assert!(event.is_some());
    }
}

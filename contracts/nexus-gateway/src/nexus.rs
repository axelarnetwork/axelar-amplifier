use std::str::FromStr;

use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::nonempty;
use cosmwasm_std::{Coin, CosmosMsg, CustomMsg};
use error_stack::{Report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractError;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
// this matches the message type defined in the nexus module
// https://github.com/axelarnetwork/axelar-core/blob/6c887df3797ba660093061662aff04e325b9c429/x/nexus/exported/types.pb.go#L405
pub struct Message {
    pub source_chain: ChainNameRaw,
    pub source_address: Address,
    pub destination_chain: ChainName,
    pub destination_address: Address,
    pub payload_hash: [u8; 32],
    pub source_tx_id: nonempty::Vec<u8>,
    pub source_tx_index: u64,
    pub id: String,
    pub token: Option<Coin>,
}

impl CustomMsg for Message {}

// it's parsed into u64 instead of u32 (https://github.com/axelarnetwork/axelar-amplifier/blob/bf0b3049c83e540989c7dad1c609c7e2ef6ed2e5/contracts/voting-verifier/src/events.rs#L162)
// here in order to match the message type defined in the nexus module. Changing nexus to use u32 instead is not worth the effort.
fn parse_message_id(message_id: &str) -> Result<(nonempty::Vec<u8>, u64), ContractError> {
    let id = HexTxHashAndEventIndex::from_str(message_id)
        .change_context(ContractError::InvalidMessageId(message_id.into()))?;
    let tx_id = nonempty::Vec::<u8>::try_from(id.tx_hash.to_vec())
        .change_context(ContractError::InvalidMessageId(message_id.into()))?;

    Ok((tx_id, id.event_index.into()))
}

impl From<router_api::Message> for Message {
    fn from(msg: router_api::Message) -> Self {
        // fallback to using all 0's as the tx ID if it's not in the expected format
        let (source_tx_id, source_tx_index) =
            parse_message_id(&msg.cc_id.message_id).unwrap_or((vec![0; 32].try_into().unwrap(), 0));

        Self {
            source_chain: msg.cc_id.source_chain,
            source_address: msg.source_address,
            destination_chain: msg.destination_chain,
            destination_address: msg.destination_address,
            payload_hash: msg.payload_hash,
            source_tx_id,
            source_tx_index,
            id: msg.cc_id.message_id.into(),
            token: None,
        }
    }
}

impl TryFrom<Message> for router_api::Message {
    type Error = Report<ContractError>;

    fn try_from(msg: Message) -> Result<Self, ContractError> {
        Ok(Self {
            cc_id: CrossChainId {
                source_chain: msg.source_chain,
                message_id: nonempty::String::try_from(msg.id.as_str())
                    .change_context(ContractError::InvalidMessageId(msg.id))?,
            },
            source_address: msg.source_address,
            destination_chain: msg.destination_chain,
            destination_address: msg.destination_address,
            payload_hash: msg.payload_hash,
        })
    }
}

impl From<Message> for CosmosMsg<Message> {
    fn from(msg: Message) -> Self {
        CosmosMsg::Custom(msg)
    }
}

#[cfg(test)]
mod test {
    use std::vec;

    use axelar_wasm_std::msg_id::{Base58TxDigestAndEventIndex, HexTxHashAndEventIndex};
    use router_api::CrossChainId;

    use super::Message;

    #[test]
    fn should_convert_nexus_message_to_router_message() {
        let msg_id = HexTxHashAndEventIndex {
            tx_hash: vec![2; 32].try_into().unwrap(),
            event_index: 1,
        };
        let msg = Message {
            source_chain: "ethereum".parse().unwrap(),
            source_address: "something".parse().unwrap(),
            destination_chain: "polygon".parse().unwrap(),
            destination_address: "something else".parse().unwrap(),
            payload_hash: [1; 32],
            source_tx_id: msg_id.tx_hash.to_vec().try_into().unwrap(),
            source_tx_index: msg_id.event_index as u64,
            id: msg_id.to_string(),
            token: None,
        };

        let router_msg = router_api::Message::try_from(msg.clone());
        assert!(router_msg.is_ok());
        let router_msg = router_msg.unwrap();
        let router_msg_cc_id = router_msg.cc_id;
        assert_eq!(router_msg_cc_id.source_chain, msg.source_chain);
        assert_eq!(router_msg_cc_id.message_id.to_string(), msg.id);
    }

    #[test]
    fn should_convert_router_message_to_nexus_message() {
        let msg = router_api::Message {
            cc_id: CrossChainId::new(
                "ethereum",
                HexTxHashAndEventIndex {
                    tx_hash: [2; 32],
                    event_index: 1,
                }
                .to_string()
                .as_str(),
            )
            .unwrap(),
            source_address: "something".parse().unwrap(),
            destination_chain: "polygon".parse().unwrap(),
            destination_address: "something else".parse().unwrap(),
            payload_hash: [1; 32],
        };

        let nexus_msg = Message::from(msg.clone());

        let router_msg_cc_id = msg.cc_id;

        assert_eq!(nexus_msg.id, *router_msg_cc_id.message_id);
        assert_eq!(nexus_msg.destination_address, msg.destination_address);
        assert_eq!(nexus_msg.destination_chain, msg.destination_chain);
        assert_eq!(nexus_msg.source_address, msg.source_address);
        assert_eq!(
            nexus_msg.source_chain,
            router_msg_cc_id.source_chain.clone()
        );
        assert_eq!(nexus_msg.source_tx_id, vec![2; 32].try_into().unwrap());
        assert_eq!(nexus_msg.source_tx_index, 1);
    }

    #[test]
    fn should_convert_router_message_with_non_hex_msg_id_to_nexus_message() {
        let msg = router_api::Message {
            cc_id: CrossChainId::new(
                "ethereum",
                Base58TxDigestAndEventIndex {
                    tx_digest: [2; 32],
                    event_index: 1,
                }
                .to_string()
                .as_str(),
            )
            .unwrap(),
            source_address: "something".parse().unwrap(),
            destination_chain: "polygon".parse().unwrap(),
            destination_address: "something else".parse().unwrap(),
            payload_hash: [1; 32],
        };

        let nexus_msg = Message::from(msg.clone());

        let router_msg_cc_id = msg.cc_id;

        assert_eq!(nexus_msg.id, *router_msg_cc_id.message_id);
        assert_eq!(nexus_msg.source_tx_id, vec![0; 32].try_into().unwrap());
        assert_eq!(nexus_msg.source_tx_index, 0);

        assert_eq!(nexus_msg.destination_address, msg.destination_address);
        assert_eq!(nexus_msg.destination_chain, msg.destination_chain);
        assert_eq!(nexus_msg.source_address, msg.source_address);
        assert_eq!(
            nexus_msg.source_chain,
            router_msg_cc_id.source_chain.clone()
        );
    }
}

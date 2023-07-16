use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary, Uint256};
use ethabi::{ethereum_types, Token};
use std::{fmt::Display, str::FromStr};

use crate::error::ContractError;

pub type KeccackHash = [u8; 32]; // TODO: move to axelar_wasm_std, probably change to newtype with hex encoding (HexBinary/[u8;32])

pub struct Message {
    pub id: String,
    pub source_address: String,
    pub source_chain: String,
    pub destination_address: ethereum_types::Address,
    pub payload_hash: KeccackHash,
}

impl TryFrom<connection_router::msg::Message> for Message {
    type Error = ContractError;

    fn try_from(msg: connection_router::msg::Message) -> Result<Self, Self::Error> {
        Ok(Message {
            id: msg.id,
            source_address: msg.source_address,
            source_chain: msg.source_chain,
            destination_address: ethereum_types::Address::from_str(&msg.destination_address)
                .map_err(|_| ContractError::InvalidMessage {
                    context: "destination_address is not a valid EVM address".into(),
                })?,
            payload_hash: msg.payload_hash.as_slice().try_into().map_err(|_| {
                ContractError::InvalidMessage {
                    context: "payload_hash is not a valid keccak256 hash".into(),
                }
            })?,
        })
    }
}

// TODO: this would most likely change when other command types are supported
impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "approveContractCall")
    }
}

#[cw_serde]
pub struct Data {
    pub destination_chain_id: Uint256,
    pub commands_ids: Vec<[u8; 32]>,
    pub commands_types: Vec<String>,
    pub commands_params: Vec<HexBinary>,
}

impl Data {
    pub fn encode(&self) -> HexBinary {
        let destination_chain_id = Token::Uint(
            ethereum_types::U256::from_dec_str(&self.destination_chain_id.to_string())
                .expect("violated invariant: Uint256 is not a valid EVM uint256"),
        );
        let commands_ids: Vec<Token> = self
            .commands_ids
            .iter()
            .map(|item| Token::FixedBytes(item.to_vec()))
            .collect();
        let commands_types: Vec<Token> = self
            .commands_types
            .iter()
            .map(|item| Token::String(item.into()))
            .collect();
        let commands_params: Vec<Token> = self
            .commands_params
            .iter()
            .map(|item| Token::Bytes(item.to_vec()))
            .collect();

        ethabi::encode(&[
            destination_chain_id,
            Token::Array(commands_ids),
            Token::Array(commands_types),
            Token::Array(commands_params),
        ])
        .into()
    }
}

#[cw_serde]
pub struct Proof {
    pub operators: Vec<Addr>,
    pub weights: Vec<Uint256>,
    pub threshold: Uint256,
    pub signatures: Vec<HexBinary>,
}

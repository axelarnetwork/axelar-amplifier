use std::collections::HashMap;

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;

use crate::ContractError;

pub trait VerifiableSignature {
    fn verify(&self, msg: &Message, pub_key: &PublicKey) -> Result<bool, ContractError>;
}

#[cw_serde]
pub struct PublicKey(HexBinary);

impl From<PublicKey> for HexBinary {
    fn from(original: PublicKey) -> Self {
        original.0
    }
}

impl<'a> From<&'a PublicKey> for &'a [u8] {
    fn from(original: &'a PublicKey) -> Self {
        original.0.as_slice()
    }
}

impl PublicKey {
    pub fn unchecked(hex: HexBinary) -> Self {
        Self(hex)
    }
}

#[cw_serde]
pub struct Message(HexBinary);

impl From<Message> for HexBinary {
    fn from(original: Message) -> Self {
        original.0
    }
}

impl<'a> From<&'a Message> for &'a [u8] {
    fn from(original: &'a Message) -> Self {
        original.0.as_slice()
    }
}

impl Message {
    pub fn unchecked(hex: HexBinary) -> Self {
        Self(hex)
    }
}

#[cw_serde]
pub struct Signature(HexBinary);

impl From<Signature> for HexBinary {
    fn from(original: Signature) -> Self {
        original.0
    }
}

impl<'a> From<&'a Signature> for &'a [u8] {
    fn from(original: &'a Signature) -> Self {
        original.0.as_slice()
    }
}

impl Signature {
    pub fn unchecked(hex: HexBinary) -> Self {
        Self(hex)
    }
}

#[cw_serde]
pub struct Key {
    pub id: String,
    pub snapshot: Snapshot,
    pub pub_keys: HashMap<String, PublicKey>,
}

#[cw_serde]
pub enum MultisigState {
    Pending,
    Completed,
}

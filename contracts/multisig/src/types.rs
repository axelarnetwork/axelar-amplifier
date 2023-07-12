use std::{collections::HashMap, fmt};

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, HexBinary};

use crate::ContractError;

pub trait VerifiableSignature {
    fn verify(&self, msg: &MsgToSign, pub_key: &PublicKey) -> Result<bool, ContractError>;
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
pub struct MsgToSign(HexBinary);

impl From<MsgToSign> for HexBinary {
    fn from(original: MsgToSign) -> Self {
        original.0
    }
}

impl<'a> From<&'a MsgToSign> for &'a [u8] {
    fn from(original: &'a MsgToSign) -> Self {
        original.0.as_slice()
    }
}

impl MsgToSign {
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
pub struct KeyID {
    owner: Addr,
    subkey: String,
}

impl From<(Addr, String)> for KeyID {
    fn from(original: (Addr, String)) -> Self {
        Self {
            owner: original.0,
            subkey: original.1,
        }
    }
}

impl<'a> From<&'a KeyID> for (&'a Addr, &'a str) {
    fn from(original: &'a KeyID) -> Self {
        (&original.owner, &original.subkey)
    }
}

impl fmt::Display for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.owner, self.subkey)
    }
}

#[cw_serde]
pub struct Key {
    pub id: KeyID,
    pub snapshot: Snapshot,
    pub pub_keys: HashMap<String, PublicKey>,
}

#[cw_serde]
pub enum MultisigState {
    Pending,
    Completed,
}

use std::{collections::HashMap, fmt};

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_binary, Addr, HexBinary, StdResult};
use cw_storage_plus::{KeyDeserialize, PrimaryKey};

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
    pub owner: Addr,
    pub subkey: String,
}

impl<'a> PrimaryKey<'a> for &KeyID {
    type Prefix = Addr;
    type SubPrefix = ();
    type Suffix = String;
    type SuperSuffix = KeyID;

    fn key(&self) -> std::vec::Vec<cw_storage_plus::Key<'_>> {
        let mut keys = self.owner.key();
        keys.extend(self.subkey.key());
        keys
    }
}

impl KeyDeserialize for KeyID {
    type Output = KeyID;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(from_binary(&value.into()).expect("violated invariant: KeyID is not deserializable"))
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

#[cfg(test)]
mod tests {
    use cosmwasm_std::to_binary;

    use super::*;

    #[test]
    fn test_key_deserialize() {
        let key = KeyID {
            owner: Addr::unchecked("owner".to_string()),
            subkey: "subkey".to_string(),
        };

        let serialized = to_binary(&key).unwrap();

        assert_eq!(key, KeyID::from_vec(serialized.into()).unwrap());
    }
}

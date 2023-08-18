use std::{collections::HashMap, fmt};

use axelar_wasm_std::Snapshot;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_binary, Addr, HexBinary, StdError, StdResult};
use cw_storage_plus::{KeyDeserialize, PrimaryKey};

use crate::{secp256k1::ecdsa_verify, ContractError};

pub trait VerifiableSignature {
    fn verify(&self, msg: &MsgToSign, pub_key: &PublicKey) -> Result<bool, ContractError>;
}

#[cw_serde]
pub enum KeyType {
    ECDSA,
}

impl<'a> PrimaryKey<'a> for KeyType {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<cw_storage_plus::Key> {
        vec![cw_storage_plus::Key::Val8(
            vec![self.clone() as u8]
                .try_into()
                .expect("failed to serialize key type"),
        )]
    }
}

impl KeyDeserialize for KeyType {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        serde_json::from_slice(value.as_slice()).map_err(|err| StdError::ParseErr {
            target_type: "KeyType".into(),
            msg: err.to_string(),
        })
    }
}

#[cw_serde]
pub enum PublicKey {
    ECDSA(ECDSAPublicKey),
}

impl TryFrom<(KeyType, HexBinary)> for PublicKey {
    type Error = ContractError;

    fn try_from((key_type, pub_key): (KeyType, HexBinary)) -> Result<Self, Self::Error> {
        match key_type {
            KeyType::ECDSA => ECDSAPublicKey::try_from(pub_key).map(PublicKey::ECDSA),
        }
    }
}

impl<'a> From<&'a PublicKey> for &'a [u8] {
    fn from(value: &'a PublicKey) -> Self {
        match value {
            PublicKey::ECDSA(pub_key) => pub_key.into(),
        }
    }
}

#[cw_serde]
pub struct ECDSAPublicKey(HexBinary);

impl From<ECDSAPublicKey> for HexBinary {
    fn from(original: ECDSAPublicKey) -> Self {
        original.0
    }
}

impl<'a> From<&'a ECDSAPublicKey> for &'a [u8] {
    fn from(original: &'a ECDSAPublicKey) -> Self {
        original.0.as_slice()
    }
}

impl ECDSAPublicKey {
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
#[derive(Ord, PartialOrd, Eq)]
pub enum Signature {
    ECDSA(ECDSASignature),
}

impl From<Signature> for HexBinary {
    fn from(value: Signature) -> Self {
        match value {
            Signature::ECDSA(sig) => sig.into(),
        }
    }
}

impl TryFrom<(PublicKey, HexBinary)> for Signature {
    type Error = ContractError;

    fn try_from((pk, sig): (PublicKey, HexBinary)) -> Result<Self, Self::Error> {
        match pk {
            PublicKey::ECDSA(_) => ECDSASignature::try_from(sig).map(Signature::ECDSA),
        }
    }
}

#[cw_serde]
#[derive(Ord, PartialOrd, Eq)]
pub struct ECDSASignature(HexBinary);

impl From<ECDSASignature> for HexBinary {
    fn from(original: ECDSASignature) -> Self {
        original.0
    }
}

impl From<&ECDSASignature> for Vec<u8> {
    fn from(original: &ECDSASignature) -> Self {
        original.0.to_vec()
    }
}

impl<'a> From<&'a ECDSASignature> for &'a [u8] {
    fn from(original: &'a ECDSASignature) -> Self {
        original.0.as_slice()
    }
}

impl ECDSASignature {
    pub fn unchecked(hex: HexBinary) -> Self {
        Self(hex)
    }
}

impl VerifiableSignature for Signature {
    fn verify(&self, msg: &MsgToSign, pub_key: &PublicKey) -> Result<bool, ContractError> {
        match (self, pub_key) {
            (Signature::ECDSA(sig), PublicKey::ECDSA(pub_key)) => ecdsa_verify(msg, sig, pub_key),
        }
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

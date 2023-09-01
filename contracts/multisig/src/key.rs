use cosmwasm_schema::cw_serde;
use cosmwasm_std::{HexBinary, StdError, StdResult};
use cw_storage_plus::{KeyDeserialize, PrimaryKey};

use crate::{
    secp256k1::ecdsa_verify,
    types::{MsgToSign, VerifiableSignature},
    ContractError,
};

#[cw_serde]
pub enum KeyType {
    Ecdsa,
}

#[cw_serde]
#[derive(PartialOrd, Ord, Eq)]
pub enum Signature {
    Ecdsa(HexBinary),
}

#[cw_serde]
pub enum PublicKey {
    Ecdsa(HexBinary),
}

pub trait KeyTyped {
    fn matches<T>(&self, other: &T) -> bool
    where
        T: KeyTyped,
    {
        self.key_type() == other.key_type()
    }

    fn key_type(&self) -> KeyType;
}

impl KeyTyped for PublicKey {
    fn key_type(&self) -> KeyType {
        match self {
            PublicKey::Ecdsa(_) => KeyType::Ecdsa,
        }
    }
}

impl KeyTyped for Signature {
    fn key_type(&self) -> KeyType {
        match self {
            Signature::Ecdsa(_) => KeyType::Ecdsa,
        }
    }
}

impl VerifiableSignature for Signature {
    fn verify(&self, msg: &MsgToSign, pub_key: &PublicKey) -> Result<bool, ContractError> {
        if !self.matches(pub_key) {
            return Err(ContractError::KeyTypeMismatch);
        }

        match (self, pub_key) {
            (Signature::Ecdsa(sig), PublicKey::Ecdsa(pub_key)) => {
                ecdsa_verify(msg.into(), sig.as_ref(), pub_key.as_ref())
            }
        }
    }
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

const ECDSA_COMPRESSED_PUBKEY_LEN: usize = 33;
const ECDSA_UNCOMPRESSED_PUBKEY_LEN: usize = 65;
const EVM_SIGNATURE_LEN: usize = 65;

impl TryFrom<(KeyType, HexBinary)> for PublicKey {
    type Error = ContractError;

    fn try_from((key_type, pub_key): (KeyType, HexBinary)) -> Result<Self, Self::Error> {
        match key_type {
            KeyType::Ecdsa => {
                if pub_key.len() != ECDSA_COMPRESSED_PUBKEY_LEN
                    && pub_key.len() != ECDSA_UNCOMPRESSED_PUBKEY_LEN
                {
                    return Err(ContractError::InvalidPublicKeyFormat {
                        reason: "Invalid input length".into(),
                    });
                }
                Ok(PublicKey::Ecdsa(pub_key))
            }
        }
    }
}

impl TryFrom<(KeyType, HexBinary)> for Signature {
    type Error = ContractError;

    fn try_from((key_type, sig): (KeyType, HexBinary)) -> Result<Self, Self::Error> {
        match key_type {
            KeyType::Ecdsa => {
                if sig.len() != EVM_SIGNATURE_LEN {
                    return Err(ContractError::InvalidSignatureFormat {
                        reason: "Invalid input length".into(),
                    });
                }
                Ok(Signature::Ecdsa(sig))
            }
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            PublicKey::Ecdsa(pk) => pk.as_ref(),
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::Ecdsa(sig) => sig.as_ref(),
        }
    }
}

impl From<Signature> for Vec<u8> {
    fn from(value: Signature) -> Vec<u8> {
        match value {
            Signature::Ecdsa(sig) => sig.to_vec(),
        }
    }
}

impl From<Signature> for HexBinary {
    fn from(original: Signature) -> Self {
        match original {
            Signature::Ecdsa(sig) => sig,
        }
    }
}

impl From<PublicKey> for HexBinary {
    fn from(original: PublicKey) -> Self {
        match original {
            PublicKey::Ecdsa(sig) => sig,
        }
    }
}

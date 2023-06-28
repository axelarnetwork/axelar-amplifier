// TODO: Logic specific to secp256k1 will most likely be handled by core in the future.
use crate::{
    types::{Message, PublicKey, Signature},
    ContractError,
};

impl TryFrom<&PublicKey> for secp256k1::PublicKey {
    type Error = ContractError;

    fn try_from(other: &PublicKey) -> Result<Self, Self::Error> {
        secp256k1::PublicKey::parse_slice(&other.0, None).map_err(|err| {
            ContractError::InvalidPublicKeyFormat {
                context: err.to_string(),
            }
        })
    }
}

impl TryFrom<&Message> for secp256k1::Message {
    type Error = ContractError;

    fn try_from(other: &Message) -> Result<Self, Self::Error> {
        secp256k1::Message::parse_slice(other.0.as_slice()).map_err(|err| {
            ContractError::InvalidMessageFormat {
                context: err.to_string(),
            }
        })
    }
}

impl TryFrom<&Signature> for secp256k1::Signature {
    type Error = ContractError;

    fn try_from(other: &Signature) -> Result<Self, Self::Error> {
        secp256k1::Signature::parse_der(&other.0).map_err(|err| {
            ContractError::InvalidSignatureFormat {
                context: err.to_string(),
            }
        })
    }
}

pub trait Secp256k1Signature {
    fn verify(&self, msg: &Message, pub_key: &PublicKey) -> Result<bool, ContractError>;
}

impl Secp256k1Signature for Signature {
    fn verify(&self, msg: &Message, pub_key: &PublicKey) -> Result<bool, ContractError> {
        Ok(secp256k1::verify(
            &msg.try_into()?,
            &self.try_into()?,
            &pub_key.try_into()?,
        ))
    }
}

use std::fmt;

use cosmwasm_std::HexBinary;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use error_stack::{self, report, Report, ResultExt};
use thiserror::Error;

pub type CosmosPublicKey = cosmrs::crypto::PublicKey;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("cosmos does not support key {0}")]
    UnsupportedConversionForCosmosKey(PublicKey),
    #[error("invalid raw bytes")]
    InvalidRawBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum PublicKey {
    Secp256k1(k256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    // TODO: add support for Schnorr
    Schnorr,
}

impl PublicKey {
    pub fn new_secp256k1(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Ok(PublicKey::Secp256k1(
            k256::ecdsa::VerifyingKey::from_sec1_bytes(bytes.as_ref())
                .change_context(Error::InvalidRawBytes)?,
        ))
    }

    pub fn new_ed25519(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Ok(PublicKey::Ed25519(
            ed25519_dalek::VerifyingKey::from_bytes(
                &<[u8; PUBLIC_KEY_LENGTH]>::try_from(bytes.as_ref())
                    .change_context(Error::InvalidRawBytes)?,
            )
            .change_context(Error::InvalidRawBytes)?,
        ))
    }

    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            PublicKey::Secp256k1(key) => key.to_sec1_bytes().to_vec(),
            PublicKey::Ed25519(key) => key.to_bytes().to_vec(),
            PublicKey::Schnorr => todo!("schnorr keys are not supported yet"),
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKey::Secp256k1(key) => {
                write!(
                    f,
                    "secp256k1: {}",
                    HexBinary::from(key.to_sec1_bytes().to_vec()).to_hex()
                )
            }
            PublicKey::Ed25519(key) => {
                write!(f, "ed25519: {}", HexBinary::from(key.to_bytes()).to_hex())
            }
            PublicKey::Schnorr => todo!("schnorr keys are not supported yet"),
        }
    }
}

impl TryFrom<&multisig::key::PublicKey> for PublicKey {
    type Error = Report<Error>;

    fn try_from(key: &multisig::key::PublicKey) -> Result<Self> {
        match key {
            multisig::key::PublicKey::Ecdsa(key) => Self::new_secp256k1(key),
            multisig::key::PublicKey::Ed25519(key) => Self::new_ed25519(key),
        }
    }
}

impl TryFrom<multisig::key::PublicKey> for PublicKey {
    type Error = Report<Error>;

    fn try_from(key: multisig::key::PublicKey) -> Result<Self> {
        (&key).try_into()
    }
}

impl TryFrom<&PublicKey> for CosmosPublicKey {
    type Error = Report<Error>;

    fn try_from(key: &PublicKey) -> Result<Self> {
        match key {
            PublicKey::Secp256k1(key) => Ok(key.into()),
            PublicKey::Ed25519(key) => Ok(cosmrs::tendermint::PublicKey::from_raw_ed25519(
                &key.to_bytes(),
            )
            .expect("must be valid ed25519 key")
            .into()),
            PublicKey::Schnorr => Err(report!(Error::UnsupportedConversionForCosmosKey(*key))),
        }
    }
}

impl TryFrom<PublicKey> for CosmosPublicKey {
    type Error = Report<Error>;

    fn try_from(key: PublicKey) -> Result<Self> {
        (&key).try_into()
    }
}

impl From<&CosmosPublicKey> for PublicKey {
    fn from(key: &CosmosPublicKey) -> Self {
        match key.type_url() {
            CosmosPublicKey::SECP256K1_TYPE_URL => Self::new_secp256k1(key.to_bytes()),
            CosmosPublicKey::ED25519_TYPE_URL => Self::new_ed25519(key.to_bytes()),
            _ => unreachable!("unknown cosmos pubic key type"),
        }
        .expect("must be valid cosmos key")
    }
}

impl From<CosmosPublicKey> for PublicKey {
    fn from(key: CosmosPublicKey) -> Self {
        (&key).into()
    }
}

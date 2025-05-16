use std::fmt;

use cosmwasm_std::HexBinary;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use error_stack::{self, Report, ResultExt};
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

#[cfg(test)]
pub mod test_utils {
    use rand::rngs::OsRng;

    use super::CosmosPublicKey;

    pub fn random_cosmos_public_key() -> CosmosPublicKey {
        CosmosPublicKey::from(k256::ecdsa::SigningKey::random(&mut OsRng).verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::assert_err_contains;
    use rand::random;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn new_secp256k1() {
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let bytes = verifying_key.to_sec1_bytes();
        let public_key = PublicKey::new_secp256k1(&bytes).unwrap();
        assert_eq!(public_key.to_bytes(), bytes.to_vec());

        let bytes: [u8; 20] = random();
        assert_err_contains!(
            PublicKey::new_secp256k1(bytes),
            Error,
            Error::InvalidRawBytes,
        );
    }

    #[test]
    fn new_ed25519() {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let bytes = verifying_key.to_bytes();
        let public_key = PublicKey::new_ed25519(bytes).unwrap();
        assert_eq!(public_key.to_bytes(), bytes.to_vec());

        let bytes: [u8; 20] = random();
        assert_err_contains!(PublicKey::new_ed25519(bytes), Error, Error::InvalidRawBytes,);
    }

    #[test]
    fn conversion_to_cosmos_public_key() {
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let bytes = verifying_key.to_sec1_bytes();
        let public_key = PublicKey::new_secp256k1(&bytes).unwrap();
        let cosmos_public_key: CosmosPublicKey = public_key.try_into().unwrap();
        assert_eq!(cosmos_public_key.to_bytes(), bytes.to_vec());

        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let bytes = verifying_key.to_bytes();
        let public_key = PublicKey::new_ed25519(bytes).unwrap();
        let cosmos_public_key: CosmosPublicKey = public_key.try_into().unwrap();
        assert_eq!(cosmos_public_key.to_bytes(), bytes.to_vec());
    }
}

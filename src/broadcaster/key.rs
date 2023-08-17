use cosmrs::bip32::secp256k1::elliptic_curve::rand_core::OsRng;
use hex::{self, FromHex};
use thiserror::Error;

use crate::types::TMAddress;

const PREFIX: &str = "axelar";

/// In contrast to cosmrs::crypto::secp256k1::SigningKey, this key type is sendable so it can be used in contexts when it needs to be moved across thread boundaries
#[derive(Debug, Clone)]
pub struct ECDSASigningKey {
    inner: k256::ecdsa::SigningKey,
}

impl ECDSASigningKey {
    pub fn public_key(&self) -> cosmrs::crypto::PublicKey {
        self.inner.verifying_key().into()
    }

    pub fn random() -> Self {
        Self {
            inner: ecdsa::SigningKey::random(&mut OsRng),
        }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, ecdsa::Error> {
        Ok(Self {
            inner: ecdsa::SigningKey::from_slice(bytes)?,
        })
    }

    pub fn address(&self) -> TMAddress {
        self.public_key()
            .account_id(PREFIX)
            .expect("failed to convert to account identifier")
            .into()
    }
}

impl From<&ECDSASigningKey> for cosmrs::crypto::secp256k1::SigningKey {
    fn from(key: &ECDSASigningKey) -> cosmrs::crypto::secp256k1::SigningKey {
        let signing_key = key.inner.clone();
        cosmrs::crypto::secp256k1::SigningKey::new(Box::new(signing_key))
    }
}

/// The error type for decoding a hex string into ECDSASigningKey
#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    FromHex(#[from] hex::FromHexError),
    #[error("{0}")]
    Ecdsa(#[from] ecdsa::Error),
}

impl FromHex for ECDSASigningKey {
    type Error = Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(Self::from_slice(<[u8; 32]>::from_hex(hex)?.as_slice())?)
    }
}

#[cfg(test)]
mod tests {
    use super::ECDSASigningKey;

    #[test]
    fn load_key_from_slice() {
        let expected_key = ECDSASigningKey::random();
        let key = ECDSASigningKey::from_slice(expected_key.inner.to_bytes().as_slice()).unwrap();

        assert_eq!(expected_key.public_key(), key.public_key());
    }
}

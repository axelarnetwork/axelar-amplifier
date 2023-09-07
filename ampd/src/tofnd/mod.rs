use hex::{self, FromHex};
use serde::Deserialize;

use crate::url::Url;

pub mod error;
pub mod grpc;

#[allow(non_snake_case)]
mod proto {
    tonic::include_proto!("tofnd");
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub url: Url,
    pub party_uid: String,
    pub key_uid: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: "http://localhost:50051/".parse().unwrap(),
            party_uid: "ampd".into(),
            key_uid: "axelar".into(),
        }
    }
}

// Signature is an alias for signature in raw bytes
pub type Signature = Vec<u8>;

#[derive(Clone, Debug, Deserialize)]
pub struct MessageDigest([u8; 32]);

impl FromHex for MessageDigest {
    type Error = error::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(MessageDigest(<[u8; 32]>::from_hex(hex)?))
    }
}

impl From<MessageDigest> for Vec<u8> {
    fn from(val: MessageDigest) -> Vec<u8> {
        val.0.into()
    }
}

impl From<[u8; 32]> for MessageDigest {
    fn from(digest: [u8; 32]) -> Self {
        MessageDigest(digest)
    }
}

impl AsRef<[u8]> for MessageDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

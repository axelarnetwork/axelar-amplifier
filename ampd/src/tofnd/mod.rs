use std::time::Duration;

use hex::{self, FromHex};
use serde::{Deserialize, Serialize};

use crate::url::Url;

pub mod error;
pub mod grpc;

#[allow(non_snake_case)]
mod proto {
    tonic::include_proto!("tofnd");
}

pub use proto::Algorithm;

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct Config {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    pub url: Url,
    pub party_uid: String,
    pub key_uid: String,
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: Url::new_non_sensitive("http://localhost:50051/").unwrap(),
            party_uid: "ampd".into(),
            key_uid: "axelar".into(),
            timeout: Duration::from_secs(3),
        }
    }
}

// Signature is an alias for signature in raw bytes
pub type Signature = Vec<u8>;

#[derive(Clone, Debug, Deserialize, PartialEq)]
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

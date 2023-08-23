use std::time::Duration;

use hex::{self, FromHex};
use serde::Deserialize;

use crate::url::Url;

pub mod client;
pub mod error;

#[allow(non_snake_case)]
mod proto {
    tonic::include_proto!("tofnd");
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub url: Url,
    #[serde(with = "humantime_serde")]
    pub dail_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: "http://localhost:50051/".parse().unwrap(),
            dail_timeout: Duration::from_secs(5),
        }
    }
}

// Signature is an alias for signature in raw bytes
pub type Signature = Vec<u8>;

#[derive(Debug, Deserialize)]
pub struct MessageDigest([u8; 32]);

impl FromHex for MessageDigest {
    type Error = error::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(MessageDigest(<[u8; 32]>::from_hex(hex)?))
    }
}

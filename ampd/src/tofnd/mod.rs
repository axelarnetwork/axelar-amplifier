use std::convert::TryFrom;
use std::time::Duration;

use hex::{self, FromHex};
use serde::Deserialize;
use serde_with::{serde_as, Bytes};

use crate::url::Url;

pub mod client;
pub mod error;

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

#[serde_as]
#[derive(Debug, Deserialize, PartialEq)]
pub struct PublicKey(#[serde_as(as = "Bytes")] [u8; 33]);

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = error::Error;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        if v.len() != 33 {
            return Err(error::Error::ParsingFailed);
        }

        let mut array = [0u8; 33];
        array.copy_from_slice(&v);

        Ok(Self(array))
    }
}

impl FromHex for PublicKey {
    type Error = error::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(PublicKey(<[u8; 33]>::from_hex(hex)?))
    }
}

impl PublicKey {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
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

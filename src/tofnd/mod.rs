use std::time::Duration;

use serde::Deserialize;

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

pub type PublicKey = [u8; 33];
// Signature is an alias for signature in raw bytes
pub type Signature = Vec<u8>;

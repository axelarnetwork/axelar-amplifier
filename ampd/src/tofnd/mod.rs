use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::url::Url;

mod grpc;

#[cfg(test)]
pub use grpc::MockMultisig;
pub use grpc::{Multisig, MultisigClient};
pub use proto::Algorithm;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    GrpcConnection(#[from] tonic::transport::Error),
    #[error(transparent)]
    GrpcRequest(#[from] tonic::Status),
    #[error("invalid keygen response")]
    InvalidKeygenResponse,
    #[error("invalid sign response")]
    InvalidSignResponse,
    #[error("tofnd failed with error {0}")]
    ExecutionFailed(String),
}

#[allow(non_snake_case)]
mod proto {
    tonic::include_proto!("tofnd");
}

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
            url: Url::new_non_sensitive("http://localhost:50051/").expect("Url should be created validly"),
            party_uid: "ampd".into(),
            key_uid: "axelar".into(),
            timeout: Duration::from_secs(3),
        }
    }
}

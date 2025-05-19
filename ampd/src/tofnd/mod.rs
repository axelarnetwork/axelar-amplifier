use std::time::Duration;

use error_stack::Report;
use proto::{KeygenResponse, SignResponse};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::url::Url;

mod grpc;

#[cfg(test)]
pub use grpc::MockMultisig;
pub use grpc::{Multisig, MultisigClient};
pub use proto::Algorithm;

pub fn install_debug_hooks() {
    Report::install_debug_hook::<KeygenResponse>(|value, context| {
        context.push_body(format!("KeygenResponse: {:?}", value));
    });
    Report::install_debug_hook::<SignResponse>(|value, context| {
        context.push_body(format!("SignResponse: {:?}", value));
    });
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),
    #[error("failed to make the grpc request")]
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
    pub url: Url,
    pub party_uid: String,
    pub key_uid: String,
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: "http://localhost:50051/".parse().unwrap(),
            party_uid: "ampd".into(),
            key_uid: "axelar".into(),
            timeout: Duration::from_secs(3),
        }
    }
}

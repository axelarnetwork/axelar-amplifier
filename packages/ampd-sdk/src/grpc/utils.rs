use std::mem::discriminant;

use ampd_proto;
use ampd_proto::{BroadcastResponse, ContractsResponse, KeyId};
use axelar_wasm_std::nonempty;
use cosmrs::AccountId;
use error_stack::{Report, Result, ResultExt as _};
use report::ResultCompatExt;
use tokio::sync::{mpsc, watch};
use tonic::transport;

use crate::grpc::error::{AppError, Error};

#[derive(Debug, Clone)]
pub enum ClientMessage {
    ConnectionFailed(String),
}

#[derive(Debug, Clone)]
pub enum ConnectionState {
    Connected(transport::Channel),
    Disconnected,
    Reconnecting,
}

impl PartialEq for ConnectionState {
    fn eq(&self, other: &Self) -> bool {
        discriminant(self) == discriminant(other)
    }
}
#[derive(Clone, Debug)]
pub struct ConnectionHandle {
    pub connection_receiver: watch::Receiver<ConnectionState>,
    pub message_sender: mpsc::Sender<ClientMessage>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BroadcastClientResponse {
    pub tx_hash: String,
    pub index: u64,
}

impl From<BroadcastResponse> for BroadcastClientResponse {
    fn from(response: BroadcastResponse) -> Self {
        BroadcastClientResponse {
            tx_hash: response.tx_hash,
            index: response.index,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContractsAddresses {
    pub voting_verifier: AccountId,
    pub multisig_prover: AccountId,
    pub service_registry: AccountId,
    pub rewards: AccountId,
}

impl TryFrom<&ContractsResponse> for ContractsAddresses {
    type Error = Report<Error>;

    fn try_from(
        response: &ContractsResponse,
    ) -> core::result::Result<ContractsAddresses, Self::Error> {
        let ContractsResponse {
            voting_verifier,
            multisig_prover,
            service_registry,
            rewards,
        } = response;

        Ok(ContractsAddresses {
            voting_verifier: parse_addr(voting_verifier, "voting verifier")?,
            multisig_prover: parse_addr(multisig_prover, "multisig prover")?,
            service_registry: parse_addr(service_registry, "service registry")?,
            rewards: parse_addr(rewards, "rewards contract")?,
        })
    }
}

pub fn parse_addr(addr: &str, address_name: &'static str) -> Result<AccountId, Error> {
    addr.parse::<AccountId>()
        .change_context(AppError::InvalidAddress(address_name).into())
        .attach_printable_lazy(|| addr.to_string())
}

pub enum KeyAlgorithm {
    Ecdsa,
    Ed25519,
}

pub struct Key {
    pub id: nonempty::String,
    pub algorithm: KeyAlgorithm,
}

impl From<Key> for KeyId {
    fn from(key: Key) -> Self {
        let algorithm = match key.algorithm {
            KeyAlgorithm::Ecdsa => ampd_proto::Algorithm::Ecdsa,
            KeyAlgorithm::Ed25519 => ampd_proto::Algorithm::Ed25519,
        };

        KeyId {
            id: key.id.into(),
            algorithm: algorithm as i32,
        }
    }
}

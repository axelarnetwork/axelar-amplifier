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

/// Represents the state of a gRPC connection to the AMPD server.
///
/// This enum is used by the connection pool to communicate the connection status to clients.
#[derive(Debug, Clone)]
pub enum ConnectionState {
    /// The connection is established and ready for service calls.
    /// Contains the active gRPC transport channel.
    Connected(transport::Channel),

    /// The connection is not available and no reconnection attempt is in progress.
    /// This is the initial state when the connection pool starts, or the final state after all reconnection attempts have failed.  
    Disconnected,

    /// A reconnection attempt is currently in progress.
    /// The connection pool is actively trying to re-establish the connection after a failure.
    /// Clients should wait for the next state change rather than immediately failing their requests.
    Reconnecting,
}

impl PartialEq for ConnectionState {
    fn eq(&self, other: &Self) -> bool {
        discriminant(self) == discriminant(other)
    }
}

/// A handle that provides access to connection state changes and allows sending
/// messages to the connection pool.
///
/// This struct is used by clients to:
/// - Monitor connection state changes via the `connection_receiver`
/// - Send messages (like connection failure reports) to the connection pool
/// - Coordinate with the connection pool for automatic reconnection
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

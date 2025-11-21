use ampd_proto;
use ampd_proto::{BroadcastResponse, ContractsResponse, KeyId};
pub use axelar_wasm_std::chain::ChainName;
use axelar_wasm_std::nonempty;
use cosmrs::AccountId;
use error_stack::Report;

use crate::grpc::error::Error;

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
    pub multisig: AccountId,
    pub event_verifier: Option<AccountId>,
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
            multisig,
            event_verifier,
        } = response;

        Ok(ContractsAddresses {
            voting_verifier: super::parse_addr(voting_verifier)?,
            multisig_prover: super::parse_addr(multisig_prover)?,
            service_registry: super::parse_addr(service_registry)?,
            rewards: super::parse_addr(rewards)?,
            multisig: super::parse_addr(multisig)?,
            event_verifier: event_verifier
                .as_ref()
                .map(|addr| super::parse_addr(addr))
                .transpose()?,
        })
    }
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

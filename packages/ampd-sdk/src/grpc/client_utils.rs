use ampd_proto;
use ampd_proto::{BroadcastResponse, ContractsResponse, KeyId};
use axelar_wasm_std::nonempty;
use cosmrs::AccountId;
use error_stack::{Report, Result, ResultExt as _};
use report::ResultCompatExt;

use crate::grpc::error::{AppError, Error};

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
            voting_verifier: parse_addr(voting_verifier)?,
            multisig_prover: parse_addr(multisig_prover)?,
            service_registry: parse_addr(service_registry)?,
            rewards: parse_addr(rewards)?,
        })
    }
}

pub(crate) fn parse_addr(addr: &str) -> Result<AccountId, Error> {
    addr.parse::<AccountId>()
        .change_context(AppError::InvalidAddress.into())
        .attach_printable(addr.to_string())
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

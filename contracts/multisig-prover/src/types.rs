use std::fmt::Display;

use axelar_wasm_std::{Participant, Snapshot};
use connection_router::state::CrossChainId;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_binary, HexBinary, StdResult, Uint256};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use multisig::{
    key::{PublicKey, Signature},
    worker_set::WorkerSet,
};
use sha3::{Digest, Keccak256};

use crate::encoding::{Data, Encoder};

#[cw_serde]
pub enum CommandType {
    ApproveContractCall,
    TransferOperatorship,
}

impl Display for CommandType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandType::ApproveContractCall => write!(f, "approveContractCall"),
            CommandType::TransferOperatorship => write!(f, "transferOperatorship"),
        }
    }
}

#[cw_serde]
pub struct Command {
    pub id: HexBinary,
    pub ty: CommandType,
    pub params: HexBinary,
}

#[cw_serde]
pub struct BatchId(HexBinary);

impl From<HexBinary> for BatchId {
    fn from(id: HexBinary) -> Self {
        Self(id)
    }
}

impl From<&[u8]> for BatchId {
    fn from(id: &[u8]) -> Self {
        Self(id.into())
    }
}

impl<'a> PrimaryKey<'a> for BatchId {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = BatchId;
    type SuperSuffix = BatchId;

    fn key(&self) -> Vec<Key> {
        vec![Key::Ref(self.0.as_slice())]
    }
}

impl KeyDeserialize for BatchId {
    type Output = BatchId;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(from_binary(&value.into()).expect("violated invariant: BatchID is not deserializable"))
    }
}

impl BatchId {
    pub fn new(message_ids: &[CrossChainId], new_worker_set: Option<WorkerSet>) -> BatchId {
        let mut message_ids = message_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        message_ids.sort();

        if let Some(new_worker_set) = new_worker_set {
            message_ids.push(new_worker_set.hash().to_string())
        }
        Keccak256::digest(message_ids.join(",")).as_slice().into()
    }
}

#[cw_serde]
pub struct CommandBatch {
    pub id: BatchId,
    pub message_ids: Vec<CrossChainId>,
    pub data: Data,
    pub encoder: Encoder,
}

#[cw_serde]
#[derive(Ord, PartialOrd, Eq)]
pub struct Operator {
    pub address: HexBinary,
    pub weight: Uint256,
    pub signature: Option<Signature>,
}

impl Operator {
    pub fn with_signature(self, sig: Signature) -> Operator {
        Operator {
            address: self.address,
            weight: self.weight,
            signature: Some(sig),
        }
    }
}

pub struct WorkersInfo {
    pub snapshot: Snapshot,
    pub pubkeys_by_participant: Vec<(Participant, PublicKey)>,
}

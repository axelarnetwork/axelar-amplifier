use std::fmt::Display;

use axelar_wasm_std::{hash::Hash, Participant, Snapshot};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{from_binary, HexBinary, StdResult, Uint256};
use cw_storage_plus::{Key, KeyDeserialize, PrimaryKey};
use multisig::{
    key::{PublicKey, Signature},
    worker_set::WorkerSet,
};
use router_api::{CrossChainId, Message};
use sha3::{Digest, Keccak256};

use crate::encoding::{abi2, Data, Encoder};

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

#[cw_serde]
pub enum Payload {
    Messages(Vec<Message>),
    WorkerSet(WorkerSet),
}

impl Payload {
    // id returns the unique identifier for the payload, which can be either
    // - the hash of comma separated sorted message ids
    // - the hash of the worker set
    pub fn id(&self) -> BatchId {
        match &self {
            Payload::Messages(msgs) => {
                let mut message_ids = msgs
                    .iter()
                    .map(|msg| msg.cc_id.to_string())
                    .collect::<Vec<_>>();
                message_ids.sort();

                Keccak256::digest(message_ids.join(",")).as_slice().into()
            }
            Payload::WorkerSet(worker_set) => worker_set.hash().into(),
        }
    }
}

#[cw_serde]
pub struct MessageToSign {
    pub id: BatchId,
    pub payload: Payload,
}

impl MessageToSign {
    pub fn new(payload: Payload) -> MessageToSign {
        MessageToSign {
            id: payload.id(),
            payload,
        }
    }

    pub fn msg_digest(
        &self,
        encoder: Encoder,
        domain_separator: &Hash,
        curr_worker_set: &WorkerSet,
    ) -> HexBinary {
        match encoder {
            Encoder::Abi => {
                abi2::message_hash_to_sign(domain_separator, curr_worker_set, &self.payload)
            }
            Encoder::Bcs => todo!(),
        }
    }

    pub fn message_ids(&self) -> Vec<CrossChainId> {
        match &self.payload {
            Payload::Messages(msgs) => msgs.iter().map(|msg| msg.cc_id.clone()).collect(),
            Payload::WorkerSet(_) => vec![],
        }
    }
}

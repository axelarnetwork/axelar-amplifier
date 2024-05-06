use cosmwasm_schema::cw_serde;
use cosmwasm_std::HexBinary;
use sha3::{Digest, Keccak256};

use axelar_wasm_std::hash::Hash;
use multisig::worker_set::WorkerSet;
use router_api::{CrossChainId, Message};

use crate::{
    encoding::{abi2, Encoder},
    types::BatchId,
};

#[cw_serde]
pub enum Payload {
    Messages(Vec<Message>),
    WorkerSet(WorkerSet),
}

impl Payload {
    /// id returns the unique identifier for the payload, which can be either
    /// - the hash of comma separated sorted message ids
    /// - the hash of the worker set
    pub fn id(&self) -> BatchId {
        match self {
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

    pub fn digest(
        &self,
        encoder: Encoder,
        domain_separator: &Hash,
        curr_worker_set: &WorkerSet,
    ) -> HexBinary {
        match encoder {
            Encoder::Abi => abi2::payload_hash_to_sign(domain_separator, curr_worker_set, self),
            Encoder::Bcs => todo!(),
        }
    }

    pub fn message_ids(&self) -> Option<Vec<CrossChainId>> {
        match &self {
            Payload::Messages(msgs) => Some(msgs.iter().map(|msg| msg.cc_id.clone()).collect()),
            Payload::WorkerSet(_) => None,
        }
    }
}

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

#[cw_serde]
pub struct Command {
    pub id: BatchId,
    pub payload: Payload,
}

impl Command {
    pub fn new(payload: Payload) -> Self {
        Command {
            id: Command::id(&payload),
            payload,
        }
    }

    pub fn digest(
        &self,
        encoder: Encoder,
        domain_separator: &Hash,
        curr_worker_set: &WorkerSet,
    ) -> HexBinary {
        match encoder {
            Encoder::Abi => {
                abi2::payload_hash_to_sign(domain_separator, curr_worker_set, &self.payload)
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

    /// id returns the unique identifier for the payload, which can be either
    /// - the hash of comma separated sorted message ids
    /// - the hash of the worker set
    fn id(payload: &Payload) -> BatchId {
        match &payload {
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

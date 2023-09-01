use axelar_wasm_std::{Snapshot, Threshold};
use connection_router::types::ChainName;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Env, HexBinary, Uint256};
use cw_storage_plus::{Item, Map};
use multisig::key::PublicKey;
use multisig::msg::Signer;
use sha3::{Digest, Keccak256};

use crate::error::ContractError;
use crate::types::{BatchID, CommandBatch};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub gateway: Addr,
    pub multisig: Addr,
    pub service_registry: Addr,
    pub destination_chain_id: Uint256,
    pub signing_threshold: Threshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub worker_set_diff_threshold: u32,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const KEY_ID: Item<String> = Item::new("key_id");
pub const COMMANDS_BATCH: Map<&BatchID, CommandBatch> = Map::new("command_batch");
pub const MULTISIG_SESSION_BATCH: Map<u64, BatchID> = Map::new("multisig_session_batch");

pub const REPLY_BATCH: Item<BatchID> = Item::new("reply_tracker");

#[cw_serde]
pub struct WorkerSet {
    pub signers: Vec<Signer>,
    pub threshold: Uint256,
    pub id: u64, // for randomness
}

impl WorkerSet {
    pub fn new(
        snapshot: Snapshot,
        pub_keys: Vec<PublicKey>,
        env: Env,
    ) -> Result<Self, ContractError> {
        let signers = pub_keys
            .into_iter()
            .zip(snapshot.participants.iter())
            .map(|(pub_key, (_, participant))| Signer {
                address: participant.address.clone(),
                weight: participant.weight.into(),
                pub_key,
            })
            .collect();

        Ok(WorkerSet {
            signers,
            threshold: snapshot.quorum.into(),
            id: env.block.height,
        })
    }

    pub fn hash(&self) -> HexBinary {
        Keccak256::digest(serde_json::to_vec(&self).expect("couldn't serialize worker set"))
            .as_slice()
            .into()
    }
}
pub const CURRENT_WORKER_SET: Item<WorkerSet> = Item::new("current_worker_set");
pub const NEXT_WORKER_SET: Item<WorkerSet> = Item::new("next_worker_set");

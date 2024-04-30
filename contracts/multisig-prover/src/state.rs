use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};
use cw_storage_plus::{Item, Map};

use axelar_wasm_std::{hash::Hash, MajorityThreshold};
use multisig::key::KeyType;
use multisig::worker_set::WorkerSet;
use router_api::ChainName;

use crate::{
    encoding::Encoder,
    payload::Payload,
    types::{BatchId, CommandBatch},
};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    #[serde(default = "default_governance")]
    pub governance: Addr,
    pub gateway: Addr,
    pub multisig: Addr,
    pub coordinator: Addr,
    pub service_registry: Addr,
    pub voting_verifier: Addr,
    pub destination_chain_id: Uint256,
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub worker_set_diff_threshold: u32,
    pub encoder: Encoder,
    pub key_type: KeyType,
    pub domain_separator: Hash,
}

// temporary, so we can read the old config from storage (that doesn't have the governance field)
fn default_governance() -> Addr {
    Addr::unchecked("axelar10d07y265gmmuvt4z0w9aw880jnsr700j7v9daj")
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const COMMANDS_BATCH: Map<&BatchId, CommandBatch> = Map::new("command_batch");
pub const PAYLOAD: Map<&BatchId, Payload> = Map::new("payload");
pub const MULTISIG_SESSION_BATCH: Map<u64, BatchId> = Map::new("multisig_session_batch");

pub const REPLY_BATCH: Item<BatchId> = Item::new("reply_tracker");

pub const CURRENT_WORKER_SET: Item<WorkerSet> = Item::new("current_worker_set");
pub const NEXT_WORKER_SET: Item<WorkerSet> = Item::new("next_worker_set");

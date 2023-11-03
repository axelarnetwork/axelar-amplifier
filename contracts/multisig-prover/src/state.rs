use axelar_wasm_std::{Snapshot, Threshold};
use connection_router::state::ChainName;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};
use cw_storage_plus::{Item, Map};
use multisig::worker_set::WorkerSet;

use crate::encoding::Encoder;
use crate::types::{BatchID, CommandBatch};

#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub gateway: Addr,
    pub multisig: Addr,
    pub service_registry: Addr,
    pub voting_verifier: Addr,
    pub destination_chain_id: Uint256,
    pub signing_threshold: Threshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub worker_set_diff_threshold: u32,
    pub encoder: Encoder,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const KEY_ID: Item<String> = Item::new("key_id");
pub const COMMANDS_BATCH: Map<&BatchID, CommandBatch> = Map::new("command_batch");
pub const MULTISIG_SESSION_BATCH: Map<u64, BatchID> = Map::new("multisig_session_batch");

pub const REPLY_BATCH: Item<BatchID> = Item::new("reply_tracker");

pub const CURRENT_WORKER_SET: Item<WorkerSet> = Item::new("current_worker_set");
pub const NEXT_WORKER_SET: Item<(WorkerSet, Snapshot)> = Item::new("next_worker_set");

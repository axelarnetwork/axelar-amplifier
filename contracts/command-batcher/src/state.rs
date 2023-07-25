use axelar_wasm_std::Threshold;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};
use cw_storage_plus::{Item, Map};

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
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const COMMANDS_BATCH: Map<&BatchID, CommandBatch> = Map::new("command_batch");

pub const REPLY_ID_COUNTER: Item<u64> = Item::new("reply_id_counter");
pub const REPLY_ID_TO_BATCH: Map<u64, BatchID> = Map::new("reply_id_to_batch");

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};
use cw_storage_plus::{Item, Map};

use crate::batch::CommandBatch;

#[cw_serde]
pub struct Config {
    pub gateway: Addr,
    pub multisig: Addr,
    pub registry: Addr,
    pub destination_chain_id: Uint256,
    pub service_name: String,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const COMMANDS_BATCH: Map<&[u8], CommandBatch> = Map::new("command_batch");

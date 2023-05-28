use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint256};
use cw_storage_plus::{Item, Map};

use crate::command::CommandBatch;

#[cw_serde]
pub struct Config {
    pub gateway: Addr,
    pub destination_chain_id: Uint256,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const COMMANDS_BATCH_QUEUE: Map<&[u8], CommandBatch> = Map::new("command_batchs");

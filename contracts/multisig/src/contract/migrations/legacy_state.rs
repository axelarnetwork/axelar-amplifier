use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::Item;

#[cw_serde]
pub struct Config {
    pub rewards_contract: Addr,
    pub block_expiry: nonempty::Uint64, // number of blocks after which a signing session expires
}

pub const CONFIG: Item<Config> = Item::new("config");

pub fn load_config(storage: &dyn Storage) -> Result<Config, cosmwasm_std::StdError> {
    CONFIG.load(storage)
}

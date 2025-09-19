use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::Item;

use crate::error::Error;

const CONFIG: Item<Config> = Item::new("config");

/// The configuration for the chain-codec contracts in this repository.
/// If you are implementing a new chain-codec implementation, you are free to use a different configuration type.
#[cw_serde]
pub struct Config {
    pub multisig_prover: Addr,
}

pub fn load_config(storage: &dyn Storage) -> Config {
    CONFIG
        .load(storage)
        .expect("config must be set during instantiation")
}

pub fn save_config(storage: &mut dyn Storage, config: &Config) -> Result<(), Error> {
    Ok(CONFIG.save(storage, config)?)
}
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::Item;

use crate::error::Error;

const CONFIG: Item<Config> = Item::new("config");

#[cw_serde]
pub struct Config {
    pub multisig_prover: Addr,
    pub chain_type: ChainType,
}

#[cw_serde]
pub enum ChainType {
    Evm,
    Sui,
    Stellar,
}

pub fn load_config(storage: &dyn Storage) -> Config {
    CONFIG
        .load(storage)
        .expect("config must be set during instantiation")
}

pub fn save_config(storage: &mut dyn Storage, config: &Config) -> Result<(), Error> {
    Ok(CONFIG.save(storage, config)?)
}

impl From<crate::msg::ChainType> for ChainType {
    fn from(value: crate::msg::ChainType) -> Self {
        match value {
            crate::msg::ChainType::Evm => Self::Evm,
            crate::msg::ChainType::Sui => Self::Sui,
            crate::msg::ChainType::Stellar => Self::Stellar,
        }
    }
}
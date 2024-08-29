use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::{Item, Map};
use error_stack::{self, ResultExt};
use router_api::CrossChainId;

use crate::error::ContractError;

const CONFIG: Item<Config> = Item::new("config");
const ROUTED_MESSAGE_IDS: Map<&CrossChainId, ()> = Map::new("routed_message_ids");

type Result<T> = error_stack::Result<T, ContractError>;

pub fn save_config(storage: &mut dyn Storage, config: Config) -> Result<()> {
    CONFIG
        .save(storage, &config)
        .change_context(ContractError::StoreFailure)
}

pub fn load_config(storage: &dyn Storage) -> Result<Config> {
    CONFIG
        .load(storage)
        .change_context(ContractError::StoreFailure)
}

pub fn set_message_routed(storage: &mut dyn Storage, id: &CrossChainId) -> Result<()> {
    ROUTED_MESSAGE_IDS
        .save(storage, id, &())
        .change_context(ContractError::StoreFailure)
}

pub fn is_message_routed(storage: &dyn Storage, id: &CrossChainId) -> Result<bool> {
    ROUTED_MESSAGE_IDS
        .may_load(storage, id)
        .map(|result| result.is_some())
        .change_context(ContractError::StoreFailure)
}

#[cw_serde]
pub struct Config {
    pub nexus: Addr,
    pub router: Addr,
    pub axelar_gateway: Addr,
}

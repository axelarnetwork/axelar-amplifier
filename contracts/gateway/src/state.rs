use crate::error::ContractError;
use connection_router::state::{CrossChainId, NewMessage};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, Storage};
use cw_storage_plus::{Item, Map};
use error_stack::{Result, ResultExt};

#[cw_serde]
pub struct Config {
    pub verifier: Addr,
    pub router: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

pub fn load_config(deps: &DepsMut) -> Config {
    CONFIG
        .load(deps.storage)
        .expect("config should be set during contract instantiation")
}

pub const OUTGOING_MESSAGES: Map<CrossChainId, NewMessage> = Map::new("outgoing_messages");

pub fn save_outgoing_msg(
    storage: &mut dyn Storage,
) -> impl FnMut(CrossChainId, &NewMessage) -> Result<(), ContractError> + '_ {
    |key, msg| {
        OUTGOING_MESSAGES
            .save(storage, key, msg)
            .change_context(ContractError::StoreOutgoingMessage)
    }
}

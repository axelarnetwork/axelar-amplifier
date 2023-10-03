use crate::error::ContractError;
use connection_router::state::{CrossChainId, Message};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::{Item, Map};
use error_stack::{Result, ResultExt};
use mockall::automock;

#[automock]
pub trait Store {
    fn load_config(&self) -> Config;
    fn save_outgoing_msg(
        &mut self,
        key: CrossChainId,
        value: &Message,
    ) -> Result<(), ContractError>;
}

#[cw_serde]
pub struct Config {
    pub verifier: Addr,
    pub router: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const OUTGOING_MESSAGES: Map<CrossChainId, Message> = Map::new("outgoing_messages");

pub struct GatewayStore<'a> {
    pub storage: &'a mut dyn Storage,
}

impl Store for GatewayStore<'_> {
    fn load_config(&self) -> Config {
        CONFIG
            .load(self.storage)
            .expect("config should be set during contract instantiation")
    }

    fn save_outgoing_msg(
        &mut self,
        key: CrossChainId,
        value: &Message,
    ) -> Result<(), ContractError> {
        OUTGOING_MESSAGES
            .save(self.storage, key, value)
            .change_context(ContractError::StoreOutgoingMessage)
    }
}

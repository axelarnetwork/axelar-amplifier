use connection_router::state::CrossChainId;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::{Item, Map};
use error_stack::{self, ResultExt};
use mockall::automock;

use crate::error::ContractError;

const CONFIG: Item<Config> = Item::new("config");
const ROUTED_MESSAGE_IDS: Map<CrossChainId, ()> = Map::new("routed_message_ids");

type Result<T> = error_stack::Result<T, ContractError>;

#[automock]
pub trait Store {
    fn save_config(&mut self, config: Config) -> Result<()>;
    fn load_config(&self) -> Result<Config>;
    fn set_message_routed(&mut self, id: &CrossChainId) -> Result<()>;
    fn is_message_routed(&self, id: &CrossChainId) -> Result<bool>;
}

pub struct GatewayStore<'a> {
    storage: &'a mut dyn Storage,
}

impl<'a> GatewayStore<'a> {
    pub fn new(storage: &'a mut dyn Storage) -> Self {
        Self { storage }
    }
}

impl Store for GatewayStore<'_> {
    fn save_config(&mut self, config: Config) -> Result<()> {
        CONFIG
            .save(self.storage, &config)
            .change_context(ContractError::StoreFailure)
    }

    fn load_config(&self) -> Result<Config> {
        CONFIG
            .load(self.storage)
            .change_context(ContractError::StoreFailure)
    }

    fn set_message_routed(&mut self, id: &CrossChainId) -> Result<()> {
        ROUTED_MESSAGE_IDS
            .save(self.storage, id.clone(), &())
            .change_context(ContractError::StoreFailure)
    }

    fn is_message_routed(&self, id: &CrossChainId) -> Result<bool> {
        ROUTED_MESSAGE_IDS
            .may_load(self.storage, id.clone())
            .map(|result| result.is_some())
            .change_context(ContractError::StoreFailure)
    }
}

#[cw_serde]
pub struct Config {
    pub nexus: Addr,
    pub router: Addr,
}

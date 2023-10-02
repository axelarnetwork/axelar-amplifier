use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage};
use cw_storage_plus::Item;

use mockall::automock;

const CONFIG: Item<Config> = Item::new("config");

#[automock]
pub trait Store {
    fn store_config(&mut self, config: Config);
    fn load_config(&self) -> Config;
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
    fn store_config(&mut self, config: Config) {
        CONFIG.save(self.storage, &config).unwrap();
    }

    fn load_config(&self) -> Config {
        CONFIG
            .load(self.storage)
            .expect("config must be set during contract instantiation")
    }
}

#[cw_serde]
pub struct Config {
    pub nexus: Addr,
    pub router: Addr,
}

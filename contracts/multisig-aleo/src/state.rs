use aleo_network_config::network::NetworkConfig;
use cosmwasm_schema::cw_serde;
use cw_storage_plus::Item;

#[cw_serde]
pub struct Config {
    pub network: NetworkConfig,
}

pub const CONFIG: Item<Config> = Item::new("config");

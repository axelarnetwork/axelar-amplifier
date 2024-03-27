use connection_router_api::ChainName;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub governance: Addr,
}
pub const CONFIG: Item<Config> = Item::new("config");

// maps chain_name -> (verifier_address, gateway_address, prover_address)
pub const CONTRACTS_PER_CHAIN: Map<ChainName, (Addr, Addr, Addr)> = Map::new("contracts_per_chain");

use connection_router_api::ChainName;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub governance: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

type ProverAddresses = Vec<Addr>;
// maps chain name to prover addresses
pub const PROVERS_PER_CHAIN: Map<ChainName, ProverAddresses> = Map::new("provers_per_chain");

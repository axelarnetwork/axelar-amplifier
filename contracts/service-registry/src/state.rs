use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::Addr;
use cw_storage_plus::Map;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Service {
    pub name: String,
    pub chain_id: String,
    pub service_worker: Addr,
    pub num_workers: u128,
    pub min_worker_bond: u128,
    pub unbonding_period: u128,
    pub description: String
}

pub const SERVICES: Map<&str, Service> = Map::new("services");

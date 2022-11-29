use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Uint64, Uint128, Coin};
use cw_storage_plus::Map;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Service {
    pub name: String,
    pub service_contract: Addr,
    pub min_num_workers: Uint64,
    pub max_num_workers: Option<Uint64>,
    pub min_worker_bond: Vec<Coin>,
    pub unbonding_period: Uint128,
    pub description: String
    // TODO: worker list should be here
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Worker {
    pub worker_address: Addr,
    pub bonded_coins: Vec<Coin>,
    pub commission_rate: Uint128,
    pub state: WorkerState
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum WorkerState {
    Active,
    Deregistering,
    Inactive
}

pub const SERVICES: Map<&str, Service> = Map::new("services");
pub const SERVICE_WORKERS: Map<(&str, &Addr), Worker> = Map::new("service_workers");

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Uint128, Coin};
use cw_storage_plus::Map;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Service {
    pub name: String,
    pub chain_id: String,
    pub service_worker: Addr,
    pub num_workers: Uint128,
    pub min_worker_bond: Vec<Coin>,
    pub unbonding_period: Uint128,
    pub description: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Worker {
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

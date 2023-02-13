use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128, Uint64};

use crate::state::Worker;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    RegisterService {
        service_name: String,
        service_contract: Addr,
        min_num_workers: Uint64,
        max_num_workers: Option<Uint64>,
        min_worker_bond: Uint128,
        unbonding_period: Uint128,
        description: String,
    },
    RegisterWorker {
        service_name: String,
        commission_rate: Uint128,
    },
    DeregisterWorker {
        service_name: String,
    },
    UnbondWorker {
        service_name: String,
        worker_address: Addr,
    },
    Delegate {
        service_name: String,
        worker_address: Addr,
        amount: Uint128,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ActiveWorkers)]
    GetActiveWorkers { service_name: String },
}

#[cw_serde]
pub struct ActiveWorkers {
    pub workers: Vec<Worker>,
}

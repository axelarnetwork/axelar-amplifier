use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

use crate::state::Worker;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    RegisterService {
        service_name: String,
        service_contract: Addr,
        min_num_workers: u16,
        max_num_workers: Option<u16>,
        min_worker_bond: Uint128,
        unbonding_period_days: u16, // number of days to wait after deregistering before allowing unbonding
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

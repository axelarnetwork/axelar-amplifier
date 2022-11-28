use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128, Coin};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    RegisterService {
        service_name: String,
        chain_id: String,
        service_worker: Addr,
        num_workers: Uint128,
        min_worker_bond: Vec<Coin>,
        unbonding_period: Uint128,
        description: String,
    },
    RegisterWorker { service_name: String, commission_rate: Uint128 },
    DeregisterWorker { service_name: String },
    UnbondWorker { service_name: String, worker_address: Addr },
    Delegate { service_name: String, worker_address: Addr, amount: Uint128 },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<ActiveWorker>)]
    GetActiveWorkers{}
}

#[cw_serde]
pub struct ActiveWorker {
    address: Addr,
    stake: Uint128,
}

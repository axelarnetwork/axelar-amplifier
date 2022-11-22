use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    RegisterService {
        service_name: String,
        chain_id: String,
        service_controller: Addr,
        num_workers: u128,
        min_worker_bond: u128,
        unbonding_period: u128,
        description: String,
    },
    AddRewards { service_name: String, rewards: u128 },
    RegisterWorker { service_name: String, worker_address: Addr, bond_amount: u128, commission_rate: u128 },
    DeregisterWorker { service_name: String, worker_address: Addr },
    Delegate { service_name: String, worker_address: Addr, amount: u128 },
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
    stake: u128,
}

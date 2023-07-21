use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

use crate::state::Worker;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_account: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // governance only
    RegisterService {
        service_name: String,
        service_contract: Addr,
        min_num_workers: u16,
        max_num_workers: Option<u16>,
        min_worker_bond: Uint128,
        unbonding_period_days: u16, // number of days to wait after deregistering before allowing unbonding
        description: String,
    },
    // governance only
    AuthorizeWorker {
        worker_addr: String,
        service_name: String,
    },

    // permissionless
    DeclareChainSupport {
        service_name: String,
        chain_name: String,
    },
    // permissionless
    BondWorker {
        service_name: String,
    },
    // permissionless
    // Removes worker from the active set and starts unbonding countdown. Call again when countdown is over to receive the previously bonded stake
    UnbondWorker {
        service_name: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ActiveWorkers)]
    GetActiveWorkers {
        service_name: String,
        chain_name: String,
    },
}

#[cw_serde]
pub struct ActiveWorkers {
    pub workers: Vec<Worker>,
}

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};

use crate::state::Worker;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_account: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Can only be called by governance account
    RegisterService {
        service_name: String,
        service_contract: Addr,
        min_num_workers: u16,
        max_num_workers: Option<u16>,
        min_worker_bond: Uint128,
        bond_denom: String,
        unbonding_period_days: u16, // number of days to wait after starting unbonding before allowed to claim stake
        description: String,
    },
    // Authorizes workers to join a service. Can only be called by governance account. Workers must still bond sufficient stake to participate.
    AuthorizeWorkers {
        workers: Vec<String>,
        service_name: String,
    },
    // Revoke authorization for specified workers. Can only be called by governance account. Workers bond remains unchanged
    UnauthorizeWorkers {
        workers: Vec<String>,
        service_name: String,
    },

    // Declares support for the specified chains. Called by the worker.
    DeclareChainSupport {
        service_name: String,
        chains: Vec<String>,
    },
    // Locks up any funds sent with the message as stake. Called by the worker.
    BondWorker {
        service_name: String,
    },
    // Initiates unbonding of staked funds. Called by the worker.
    UnbondWorker {
        service_name: String,
    },
    // Claim previously staked funds that have finished unbonding. Called by the worker.
    ClaimStake {
        service_name: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<Worker>)]
    GetActiveWorkers {
        service_name: String,
        chain_name: String,
    },
}

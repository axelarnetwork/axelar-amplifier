use connection_router_api::ChainName;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;
use multisig::worker_set::WorkerSet;
use std::collections::HashSet;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Can only be called by governance
    RegisterProverContract {
        chain_name: ChainName,
        new_prover_addr: Addr,
    },
    SetActiveVerifiers {
        next_worker_set: WorkerSet,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(WorkerSet)]
    GetActiveVerifiers { chain_name: ChainName },

    #[returns(bool)]
    CheckWorkerCanUnbond {
        worker_address: Addr,
        chains: HashSet<ChainName>,
    },
}

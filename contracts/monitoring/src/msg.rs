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
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(WorkerSet)]
    GetActiveVerifiersForChain { chain: ChainName },

    #[returns(bool)]
    CheckWorkerIsActiveForChains {
        chain_names: HashSet<ChainName>,
        worker: Addr,
    },
}

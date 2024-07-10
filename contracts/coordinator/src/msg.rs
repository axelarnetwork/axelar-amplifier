use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;
use msgs_derive::EnsurePermissions;
use router_api::ChainName;
use std::collections::HashSet;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    #[permission(Governance)]
    RegisterProverContract {
        chain_name: ChainName,
        new_prover_addr: Addr,
    },
    #[permission(Any)]
    SetActiveVerifiers { verifiers: HashSet<Addr> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(bool)]
    ReadyToUnbond { worker_address: Addr },
}

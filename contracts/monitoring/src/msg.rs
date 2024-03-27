use connection_router_api::ChainName;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};
use multisig::worker_set::WorkerSet;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Can only be called by governance account
    RegisterChainContracts {
        chain_name: ChainName,
        verifier_contract: Addr,
        gateway_contract: Addr,
        prover_contract: Addr,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(WorkerSet)]
    GetActiveVerifiersForChain { chain: ChainName },
}

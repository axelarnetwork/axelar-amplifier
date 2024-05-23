use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;

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
        next_verifier_set: VerifierSet,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(VerifierSet)]
    GetActiveVerifiers { chain_name: ChainName },
}

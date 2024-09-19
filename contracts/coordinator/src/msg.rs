use std::collections::HashSet;

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;
use msgs_derive::EnsurePermissions;
use router_api::ChainName;
use service_registry_api::msg::VerifierDetails;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
    pub service_registry: String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    #[permission(Governance)]
    RegisterProverContract {
        chain_name: ChainName,
        new_prover_addr: String,
    },
    #[permission(Specific(prover))]
    SetActiveVerifiers { verifiers: HashSet<String> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(bool)]
    ReadyToUnbond { verifier_address: String },

    #[returns(VerifierProverResponse)]
    VerifierDetailsWithProvers {
        service_name: String,
        verifier: String,
    },
}

#[cw_serde]
pub struct VerifierProverResponse {
    pub verifier_details: VerifierDetails,
    pub active_prover_set: HashSet<Addr>,
}

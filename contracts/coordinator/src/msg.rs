use std::collections::HashSet;

use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;
use msgs_derive::EnsurePermissions;
use router_api::ChainName;
use service_registry_api::Verifier;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
    pub service_registry: String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    #[permission(Governance)]
    RegisterContractAddresses {
        chain_name: ChainName,
        prover_address: String,
        gateway_address: String,
        voting_verifier_address: String,
    },
    #[permission(Specific(prover))]
    SetActiveVerifiers { verifiers: HashSet<String> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(bool)]
    ReadyToUnbond { verifier_address: String },

    #[returns(VerifierInfo)]
    VerifierInfo {
        service_name: String,
        verifier: String,
    },
}

#[cw_serde]
pub struct VerifierInfo {
    pub verifier: Verifier,
    pub weight: nonempty::Uint128,
    pub supported_chains: Vec<ChainName>,
    pub actively_signing_for: HashSet<Addr>,
}

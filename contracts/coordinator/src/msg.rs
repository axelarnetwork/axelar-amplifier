use std::collections::HashSet;

use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;
use msgs_derive::EnsurePermissions;
use router_api::ChainName;
use service_registry_api::Verifier;

use crate::state::ChainContractsRecord;

type ProverAddress = Addr;
type GatewayAddress = Addr;
type VerifierAddress = Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
    pub service_registry: String,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    #[deprecated(
        note = "Use RegisterChain instead which supports registering all contract addresses at once"
    )]
    #[permission(Governance)]
    RegisterProverContract {
        chain_name: ChainName,
        new_prover_addr: String,
    },
    #[permission(Governance)]
    RegisterChain {
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

    #[returns(ChainContractsRecord)]
    ChainContractsInfo(ChainContractsKey),
}

#[cw_serde]
pub struct VerifierInfo {
    pub verifier: Verifier,
    pub weight: nonempty::Uint128,
    pub supported_chains: Vec<ChainName>,
    pub actively_signing_for: HashSet<Addr>,
}

#[cw_serde]
pub enum ChainContractsKey {
    ChainName(ChainName),
    ProverAddress(ProverAddress),
    GatewayAddress(GatewayAddress),
    VerifierAddress(VerifierAddress),
}

#[cw_serde]
pub struct ChainContractsResponse {
    pub chain_name: ChainName,
    pub prover_address: ProverAddress,
    pub gateway_address: GatewayAddress,
    pub verifier_address: VerifierAddress,
}

impl From<ChainContractsRecord> for ChainContractsResponse {
    fn from(chain_contracts_record: ChainContractsRecord) -> Self {
        ChainContractsResponse {
            chain_name: chain_contracts_record.chain_name,
            prover_address: chain_contracts_record.prover_address,
            gateway_address: chain_contracts_record.gateway_address,
            verifier_address: chain_contracts_record.verifier_address,
        }
    }
}

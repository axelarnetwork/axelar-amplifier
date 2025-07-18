use std::collections::HashSet;

use axelar_wasm_std::address::AddressFormat;
use axelar_wasm_std::hash::Hash;
use axelar_wasm_std::msg_id::MessageIdFormat;
use axelar_wasm_std::{nonempty, MajorityThreshold};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Binary};
use msgs_derive::Permissions;
use multisig::key::KeyType;
use multisig_prover_api::encoding::Encoder;
use router_api::ChainName;
use service_registry_api::Verifier;

pub use crate::contract::MigrateMsg;

type ProverAddress = Addr;
type GatewayAddress = Addr;
type VerifierAddress = Addr;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
}

#[cw_serde]
#[derive(Permissions)]
pub enum ExecuteMsg {
    /// After the contract is instantiated, this should be the first call to execute
    #[permission(Governance)]
    RegisterProtocol {
        service_registry_address: String,
        router_address: String,
        multisig_address: String,
    },
    #[permission(Governance, Proxy(coordinator))]
    RegisterChain {
        chain_name: ChainName,
        prover_address: String,
        gateway_address: String,
        voting_verifier_address: String,
    },
    #[permission(Specific(prover))]
    SetActiveVerifiers { verifiers: HashSet<String> },

    #[permission(Governance)]
    InstantiateChainContracts {
        deployment_name: nonempty::String,
        salt: Binary,
        // Make params a Box to avoid having a large discrepancy in variant sizes
        // Such an error will be flagged by "cargo clippy..."
        params: Box<DeploymentParams>,
    },

    /// `RegisterDeployment` calls the router using `ExecuteMsgFromProxy`.
    /// Consequently, the router will enforce that the original sender has
    /// permission to register the deployment.
    #[permission(Any)]
    RegisterDeployment { deployment_name: nonempty::String },
}

#[cw_serde]
pub struct ContractDeploymentInfo<T> {
    pub code_id: u64,
    pub label: String,
    pub msg: T,
}

#[cw_serde]
pub struct ManualDeploymentParams {
    pub gateway: ContractDeploymentInfo<()>,
    pub verifier: ContractDeploymentInfo<VerifierMsg>,
    pub prover: ContractDeploymentInfo<ProverMsg>,
}

#[cw_serde]
// The parameters used to configure each instantiation.
// This is an enum to allow for additional parameter types in the future
pub enum DeploymentParams {
    Manual(ManualDeploymentParams), // user supplies all info that cannot be inferred by coordinator
}

#[cw_serde]
pub struct ProverMsg {
    pub governance_address: String,
    pub multisig_address: String,
    pub signing_threshold: MajorityThreshold,
    pub service_name: String,
    pub chain_name: ChainName,
    pub verifier_set_diff_threshold: u32,
    pub encoder: Encoder,
    pub key_type: KeyType,
    #[serde(with = "axelar_wasm_std::hex")] // (de)serialization with hex module
    #[schemars(with = "String")] // necessary attribute in conjunction with #[serde(with ...)]
    pub domain_separator: Hash,
}

#[cw_serde]
pub struct VerifierMsg {
    pub governance_address: nonempty::String,
    pub service_name: nonempty::String,
    pub source_gateway_address: nonempty::String,
    pub voting_threshold: MajorityThreshold,
    pub block_expiry: nonempty::Uint64,
    pub confirmation_height: u64,
    pub source_chain: ChainName,
    pub rewards_address: nonempty::String,
    pub msg_id_format: MessageIdFormat,
    pub address_format: AddressFormat,
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

    #[returns(ChainContractsResponse)]
    ChainContractsInfo(ChainContractsKey),
}

#[cw_serde]
pub struct VerifierInfo {
    pub verifier: Verifier,
    pub weight: nonempty::Uint128,
    pub supported_chains: Vec<ChainName>,
    pub actively_signing_for: Vec<Addr>,
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

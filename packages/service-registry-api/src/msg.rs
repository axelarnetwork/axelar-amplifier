use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use msgs_derive::Permissions;
use router_api::ChainName;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::primitives::*;

#[cw_serde]
#[derive(Permissions)]
pub enum ExecuteMsg {
    /// Can only be called by governance account
    #[permission(Governance)]
    RegisterService {
        service_name: String,
        coordinator_contract: String,
        min_num_verifiers: u16,
        max_num_verifiers: Option<u16>,
        min_verifier_bond: nonempty::Uint128,
        bond_denom: String,
        unbonding_period_days: u16, // number of days to wait after starting unbonding before allowed to claim stake
        description: String,
    },
    /// Updates modifiable fields of the service. Note, not all fields are modifiable.
    #[permission(Governance)]
    UpdateService {
        service_name: String,
        updated_service_params: UpdatedServiceParams,
    },
    /// Overrides the service params for a service and chain combination.
    #[permission(Governance)]
    OverrideServiceParams {
        service_name: String,
        chain_name: ChainName,
        service_params_override: ServiceParamsOverride,
    },
    // Removes the service params override.
    #[permission(Governance)]
    RemoveServiceParamsOverride {
        service_name: String,
        chain_name: ChainName,
    },
    /// Authorizes verifiers to join a service. Can only be called by governance account. Verifiers must still bond sufficient stake to participate.
    #[permission(Governance)]
    AuthorizeVerifiers {
        verifiers: Vec<String>,
        service_name: String,
    },
    /// Revoke authorization for specified verifiers. Can only be called by governance account. Verifiers bond remains unchanged
    #[permission(Governance)]
    UnauthorizeVerifiers {
        verifiers: Vec<String>,
        service_name: String,
    },
    /// Jail verifiers. Can only be called by governance account. Jailed verifiers are not allowed to unbond or claim stake.
    #[permission(Governance)]
    JailVerifiers {
        verifiers: Vec<String>,
        service_name: String,
    },

    /// Register support for the specified chains. Called by the verifier.
    #[permission(Specific(verifier))]
    RegisterChainSupport {
        service_name: String,
        chains: Vec<ChainName>,
    },
    /// Deregister support for the specified chains. Called by the verifier.
    #[permission(Specific(verifier))]
    DeregisterChainSupport {
        service_name: String,
        chains: Vec<ChainName>,
    },

    /// Locks up any funds sent with the message as stake. Marks the sender as a potential verifier that can be authorized.
    #[permission(Any)]
    BondVerifier { service_name: String },
    /// Initiates unbonding of staked funds for the sender.
    #[permission(Any)]
    UnbondVerifier { service_name: String },
    /// Claim previously staked funds that have finished unbonding for the sender.
    #[permission(Any)]
    ClaimStake { service_name: String },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<WeightedVerifier>)]
    ActiveVerifiers {
        service_name: String,
        chain_name: ChainName,
    },

    #[returns(Service)]
    Service {
        service_name: String,
        chain_name: Option<ChainName>,
    },

    #[returns(Option<ServiceParamsOverride>)]
    ServiceParamsOverride {
        service_name: String,
        chain_name: ChainName,
    },

    #[returns(VerifierDetails)]
    Verifier {
        service_name: String,
        verifier: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct VerifierDetails {
    pub verifier: Verifier,
    pub weight: nonempty::Uint128,
    pub supported_chains: Vec<ChainName>,
}

// Represents any modifiable fields of the Service struct
// Any non-None field overwrites the value currently stored in the Service object
#[cw_serde]
pub struct UpdatedServiceParams {
    pub min_num_verifiers: Option<u16>,
    pub max_num_verifiers: Option<Option<u16>>,
    pub min_verifier_bond: Option<nonempty::Uint128>,
    pub unbonding_period_days: Option<u16>,
}

// Represents any overrideable fields of the Service struct
// Any non-None field overrides the value currently stored in the Service object
#[cw_serde]
pub struct ServiceParamsOverride {
    pub min_num_verifiers: Option<u16>,
    pub max_num_verifiers: Option<Option<u16>>,
}

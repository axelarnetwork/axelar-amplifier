use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Timestamp};
use msgs_derive::EnsurePermissions;
use router_api::ChainName;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Can only be called by governance account
    #[permission(Governance)]
    RegisterService {
        service_name: String,
        coordinator_contract: Addr,
        min_num_verifiers: u16,
        max_num_verifiers: Option<u16>,
        min_verifier_bond: nonempty::Uint128,
        bond_denom: String,
        unbonding_period_days: u16, // number of days to wait after starting unbonding before allowed to claim stake
        description: String,
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Service {
    pub name: String,
    pub coordinator_contract: Addr,
    pub min_num_verifiers: u16,
    pub max_num_verifiers: Option<u16>,
    pub min_verifier_bond: nonempty::Uint128,
    pub bond_denom: String,
    // should be set to a duration longer than the voting period for governance proposals,
    // otherwise a verifier could bail before they get penalized
    pub unbonding_period_days: u16,
    pub description: String,
}

#[cw_serde]
pub struct WeightedVerifier {
    pub verifier_info: Verifier,
    pub weight: nonempty::Uint128,
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
    Service { service_name: String },

    #[returns(VerifierDetails)]
    Verifier {
        service_name: String,
        verifier: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Verifier {
    pub address: Addr,
    pub bonding_state: BondingState,
    pub authorization_state: AuthorizationState,
    pub service_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum BondingState {
    Bonded {
        amount: nonempty::Uint128,
    },
    RequestedUnbonding {
        amount: nonempty::Uint128,
    },
    Unbonding {
        amount: nonempty::Uint128,
        unbonded_at: Timestamp,
    },
    Unbonded,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum AuthorizationState {
    NotAuthorized,
    Authorized,
    Jailed,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct VerifierDetails {
    pub verifier: Verifier,
    pub weight: nonempty::Uint128,
    pub supported_chains: Vec<ChainName>,
}

#[cw_serde]
pub struct MigrateMsg {
    pub coordinator_contract: Addr,
}

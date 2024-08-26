use axelar_wasm_std::nonempty;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Addr;
use msgs_derive::EnsurePermissions;
use router_api::ChainName;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_account: String,
}

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

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<crate::state::WeightedVerifier>)]
    ActiveVerifiers {
        service_name: String,
        chain_name: ChainName,
    },

    #[returns(crate::state::Service)]
    Service { service_name: String },

    #[returns(crate::state::Verifier)]
    Verifier {
        service_name: String,
        verifier: String,
    },
}

#[cw_serde]
pub struct MigrateMsg {
    pub coordinator_contract: Addr,
}

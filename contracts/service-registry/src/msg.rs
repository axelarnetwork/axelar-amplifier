use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128};
use router_api::ChainName;

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_account: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Can only be called by governance account
    RegisterService {
        service_name: String,
        coordinator_contract: Addr,
        min_num_verifiers: u16,
        max_num_verifiers: Option<u16>,
        min_verifier_bond: Uint128,
        bond_denom: String,
        unbonding_period_days: u16, // number of days to wait after starting unbonding before allowed to claim stake
        description: String,
    },
    // Authorizes verifiers to join a service. Can only be called by governance account. Verifiers must still bond sufficient stake to participate.
    AuthorizeVerifiers {
        verifiers: Vec<String>,
        service_name: String,
    },
    // Revoke authorization for specified verifiers. Can only be called by governance account. Verifiers bond remains unchanged
    UnauthorizeVerifiers {
        verifiers: Vec<String>,
        service_name: String,
    },
    // Jail verifiers. Can only be called by governance account. Jailed verifiers are not allowed to unbond or claim stake.
    JailVerifiers {
        verifiers: Vec<String>,
        service_name: String,
    },

    // Register support for the specified chains. Called by the verifier.
    RegisterChainSupport {
        service_name: String,
        chains: Vec<ChainName>,
    },
    // Deregister support for the specified chains. Called by the verifier.
    DeregisterChainSupport {
        service_name: String,
        chains: Vec<ChainName>,
    },

    // Locks up any funds sent with the message as stake. Called by the verifier.
    BondVerifier {
        service_name: String,
    },
    // Initiates unbonding of staked funds. Called by the verifier.
    UnbondVerifier {
        service_name: String,
    },
    // Claim previously staked funds that have finished unbonding. Called by the verifier.
    ClaimStake {
        service_name: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Vec<crate::state::WeightedVerifier>)]
    GetActiveVerifiers {
        service_name: String,
        chain_name: ChainName,
    },

    #[returns(crate::state::Service)]
    GetService { service_name: String },

    #[returns(crate::state::Verifier)]
    GetVerifier {
        service_name: String,
        verifier: String,
    },
}

#[cw_serde]
pub struct MigrateMsg {
    pub coordinator_contract: Addr,
}

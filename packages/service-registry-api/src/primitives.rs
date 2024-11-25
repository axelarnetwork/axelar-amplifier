use axelar_wasm_std::{nonempty, Participant};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Timestamp};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Verifier {
    pub address: Addr,
    pub bonding_state: BondingState,
    pub authorization_state: AuthorizationState,
    pub service_name: String,
}

#[cw_serde]
pub struct WeightedVerifier {
    pub verifier_info: Verifier,
    pub weight: nonempty::Uint128,
}

impl From<WeightedVerifier> for Participant {
    fn from(verifier: WeightedVerifier) -> Participant {
        Self {
            weight: verifier.weight,
            address: verifier.verifier_info.address,
        }
    }
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

use axelar_wasm_std::{nonempty, Participant};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Timestamp, Uint128};
use cw_storage_plus::Map;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractError;

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

impl Verifier {
    pub fn bond(self, to_add: Option<nonempty::Uint128>) -> Result<Self, ContractError> {
        let amount: nonempty::Uint128 = match self.bonding_state {
            BondingState::Bonded { amount }
            | BondingState::RequestedUnbonding { amount }
            | BondingState::Unbonding {
                amount,
                unbonded_at: _,
            } => amount
                .into_inner()
                .checked_add(to_add.map(Uint128::from).unwrap_or(Uint128::zero()))
                .map_err(ContractError::Overflow)?
                .try_into()?,
            BondingState::Unbonded => to_add.ok_or(ContractError::NoFundsToBond)?,
        };

        Ok(Self {
            bonding_state: BondingState::Bonded { amount },
            ..self
        })
    }

    pub fn unbond(self, can_unbond: bool, time: Timestamp) -> Result<Self, ContractError> {
        if self.authorization_state == AuthorizationState::Jailed {
            return Err(ContractError::VerifierJailed);
        }

        let bonding_state = match self.bonding_state {
            BondingState::Bonded { amount } | BondingState::RequestedUnbonding { amount } => {
                if can_unbond {
                    BondingState::Unbonding {
                        unbonded_at: time,
                        amount,
                    }
                } else {
                    BondingState::RequestedUnbonding { amount }
                }
            }
            _ => return Err(ContractError::InvalidBondingState(self.bonding_state)),
        };

        Ok(Self {
            bonding_state,
            ..self
        })
    }

    pub fn claim_stake(
        self,
        time: Timestamp,
        unbonding_period_days: u64,
    ) -> Result<(Self, nonempty::Uint128), ContractError> {
        if self.authorization_state == AuthorizationState::Jailed {
            return Err(ContractError::VerifierJailed);
        }

        match self.bonding_state {
            BondingState::Unbonding {
                amount,
                unbonded_at,
            } if unbonded_at.plus_days(unbonding_period_days) <= time => Ok((
                Self {
                    bonding_state: BondingState::Unbonded,
                    ..self
                },
                amount,
            )),
            _ => Err(ContractError::InvalidBondingState(self.bonding_state)),
        }
    }
}

#[cw_serde]
pub struct WeightedVerifier {
    pub verifier_info: Verifier,
    pub weight: nonempty::Uint128,
}

/// For now, all verifiers have equal weight, regardless of amount bonded
pub const VERIFIER_WEIGHT: nonempty::Uint128 = nonempty::Uint128::one();

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

type ServiceName = String;
type VerifierAddress = Addr;

pub const SERVICES: Map<&ServiceName, Service> = Map::new("services");
pub const VERIFIERS: Map<(&ServiceName, &VerifierAddress), Verifier> = Map::new("verifiers");

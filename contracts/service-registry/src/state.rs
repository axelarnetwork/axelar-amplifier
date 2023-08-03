use cosmwasm_schema::cw_serde;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Timestamp, Uint128};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub governance: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

use axelar_wasm_std::snapshot::Participant;

use crate::ContractError;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Service {
    pub name: String,
    pub service_contract: Addr,
    pub min_num_workers: u16,
    pub max_num_workers: Option<u16>,
    pub min_worker_bond: Uint128,
    pub unbonding_period_days: u16,
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Worker {
    pub address: Addr,
    pub bonding_state: BondingState,
    pub authorization_state: AuthorizationState,
    pub service_name: String,
}

impl TryInto<Participant> for Worker {
    type Error = ContractError;

    fn try_into(self) -> Result<Participant, ContractError> {
        match self.bonding_state {
            BondingState::Bonded { amount } => Ok(Participant {
                address: self.address,
                weight: amount.try_into()?,
            }),
            _ => Err(ContractError::InvalidBondingState(self.bonding_state)),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum BondingState {
    Bonded {
        amount: Uint128,
    },
    RequestedUnbonding {
        amount: Uint128,
    },
    Unbonding {
        amount: Uint128,
        unbonded_at: Timestamp,
    },
    Unbonded,
}

impl BondingState {
    pub fn add_bond(self, to_add: Uint128) -> Result<Self, ContractError> {
        let amount = match self {
            BondingState::Bonded { amount }
            | BondingState::RequestedUnbonding { amount }
            | BondingState::Unbonding {
                amount,
                unbonded_at: _,
            } => amount + to_add,
            BondingState::Unbonded {} => to_add,
        };
        if amount.is_zero() {
            Err(ContractError::InvalidBondingState(self))
        } else {
            Ok(BondingState::Bonded { amount })
        }
    }

    pub fn unbond(self, can_unbond: bool, time: Timestamp) -> Result<Self, ContractError> {
        match self {
            BondingState::Bonded { amount } | BondingState::RequestedUnbonding { amount } => {
                if can_unbond {
                    Ok(BondingState::Unbonding {
                        unbonded_at: time,
                        amount,
                    })
                } else {
                    Ok(BondingState::RequestedUnbonding { amount })
                }
            }
            _ => Err(ContractError::InvalidBondingState(self)),
        }
    }
    pub fn claim_stake(
        self,
        time: Timestamp,
        unbonding_period_days: u64,
    ) -> Result<(Self, Uint128), ContractError> {
        match self {
            BondingState::Unbonding {
                amount,
                unbonded_at,
            } if unbonded_at.plus_days(unbonding_period_days) <= time => {
                Ok((BondingState::Unbonded, amount))
            }
            _ => Err(ContractError::InvalidBondingState(self)),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum AuthorizationState {
    NotAuthorized,
    Authorized,
}

// maps service_name -> Service
pub const SERVICES: Map<&str, Service> = Map::new("services");
// maps (service_name, chain_name, worker_address) -> ()
pub const WORKERS_PER_CHAIN: Map<(&str, &str, &Addr), ()> = Map::new("workers_per_chain");
// maps (service_name, worker_address) -> Worker
pub const WORKERS: Map<(&str, &Addr), Worker> = Map::new("workers");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bonded_add_bond() {
        let state = BondingState::Bonded {
            amount: Uint128::from(100u32),
        };
        let res = state.add_bond(Uint128::from(200u32));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            BondingState::Bonded {
                amount: Uint128::from(300u32)
            }
        );
    }

    #[test]
    fn test_requested_unbonding_add_bond() {
        let state = BondingState::RequestedUnbonding {
            amount: Uint128::from(100u32),
        };
        let res = state.add_bond(Uint128::from(200u32));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            BondingState::Bonded {
                amount: Uint128::from(300u32)
            }
        );
    }

    #[test]
    fn test_unbonding_add_bond() {
        let state = BondingState::Unbonding {
            amount: Uint128::from(100u32),
            unbonded_at: Timestamp::from_nanos(0),
        };
        let res = state.add_bond(Uint128::from(200u32));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            BondingState::Bonded {
                amount: Uint128::from(300u32)
            }
        );
    }

    #[test]
    fn test_unbonded_add_bond() {
        let state = BondingState::Unbonded {};
        let res = state.add_bond(Uint128::from(200u32));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            BondingState::Bonded {
                amount: Uint128::from(200u32)
            }
        );
    }

    #[test]
    fn test_zero_bond() {
        let state = BondingState::Unbonded {};
        let res = state.clone().add_bond(Uint128::from(0u32));
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ContractError::InvalidBondingState(state));
    }

    #[test]
    fn test_bonded_unbond() {
        let state = BondingState::Bonded {
            amount: Uint128::from(100u32),
        };
        let unbonded_at = Timestamp::from_nanos(0);
        let res = state.unbond(true, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            BondingState::Unbonding {
                amount: Uint128::from(100u32),
                unbonded_at
            }
        );
    }

    #[test]
    fn test_bonded_unbond_cant_unbond() {
        let state = BondingState::Bonded {
            amount: Uint128::from(100u32),
        };
        let unbonded_at = Timestamp::from_nanos(0);
        let res = state.unbond(false, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32)
            }
        );
    }

    #[test]
    fn test_requested_unbonding_unbond() {
        let state = BondingState::RequestedUnbonding {
            amount: Uint128::from(100u32),
        };
        let unbonded_at = Timestamp::from_nanos(0);
        let res = state.unbond(true, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            BondingState::Unbonding {
                amount: Uint128::from(100u32),
                unbonded_at
            }
        );
    }

    #[test]
    fn test_requested_unbonding_cant_unbond() {
        let state = BondingState::RequestedUnbonding {
            amount: Uint128::from(100u32),
        };
        let unbonded_at = Timestamp::from_nanos(0);
        let res = state.unbond(false, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32)
            }
        );
    }

    #[test]
    fn test_unbonding_unbond() {
        let unbonded_at = Timestamp::from_nanos(0);
        let state = BondingState::Unbonding {
            amount: Uint128::from(100u32),
            unbonded_at,
        };
        let res = state.clone().unbond(true, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(state.clone())
        );
        let res = state.clone().unbond(false, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ContractError::InvalidBondingState(state));
    }

    #[test]
    fn test_unbonded_unbond() {
        let state = BondingState::Unbonded {};
        let res = state.clone().unbond(true, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(state.clone())
        );
        let res = state.clone().unbond(false, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ContractError::InvalidBondingState(state));
    }

    #[test]
    fn test_bonded_claim_stake() {
        let state = BondingState::Bonded {
            amount: Uint128::from(100u32),
        };
        let res = state.clone().claim_stake(Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(state.clone())
        );
        let res = state
            .clone()
            .claim_stake(Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(state.clone())
        );
    }

    #[test]
    fn test_requested_unbonding_claim_stake() {
        let state = BondingState::RequestedUnbonding {
            amount: Uint128::from(100u32),
        };
        let res = state.clone().claim_stake(Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(state.clone())
        );
        let res = state
            .clone()
            .claim_stake(Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(state.clone())
        );
    }

    #[test]
    fn test_unbonding_claim_stake() {
        let unbonded_at = Timestamp::from_nanos(0);
        let state = BondingState::Unbonding {
            amount: Uint128::from(100u32),
            unbonded_at,
        };
        let res = state.clone().claim_stake(Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(state.clone())
        );
        let res = state
            .clone()
            .claim_stake(Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            (BondingState::Unbonded {}, Uint128::from(100u32))
        );
    }

    #[test]
    fn test_unbonded_claim_stake() {
        let state = BondingState::Unbonded {};
        let res = state.clone().claim_stake(Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(state.clone())
        );
        let res = state
            .clone()
            .claim_stake(Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(state.clone())
        );
    }
}

use connection_router_api::ChainName;
use cosmwasm_schema::cw_serde;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use cosmwasm_std::{Addr, Storage, Timestamp, Uint128};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub governance: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

use axelar_wasm_std::{nonempty, snapshot::Participant};

use crate::ContractError;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Service {
    pub name: String,
    pub service_contract: Addr,
    pub min_num_workers: u16,
    pub max_num_workers: Option<u16>,
    pub min_worker_bond: Uint128,
    pub bond_denom: String,
    // should be set to a duration longer than the voting period for governance proposals,
    // otherwise a verifier could bail before they get penalized
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

impl Worker {
    pub fn add_bond(self, to_add: Uint128) -> Result<Self, ContractError> {
        let amount = match self.bonding_state {
            BondingState::Bonded { amount }
            | BondingState::RequestedUnbonding { amount }
            | BondingState::Unbonding {
                amount,
                unbonded_at: _,
            } => amount
                .checked_add(to_add)
                .map_err(ContractError::Overflow)?,
            BondingState::Unbonded => to_add,
        };

        if amount.is_zero() {
            Err(ContractError::InvalidBondingState(self.bonding_state))
        } else {
            Ok(Self {
                bonding_state: BondingState::Bonded { amount },
                ..self
            })
        }
    }

    pub fn unbond(self, can_unbond: bool, time: Timestamp) -> Result<Self, ContractError> {
        if self.authorization_state == AuthorizationState::Jailed {
            return Err(ContractError::WorkerJailed);
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
    ) -> Result<(Self, Uint128), ContractError> {
        if self.authorization_state == AuthorizationState::Jailed {
            return Err(ContractError::WorkerJailed);
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
pub struct WeightedWorker {
    pub worker_info: Worker,
    pub weight: nonempty::Uint256,
}

/// For now, all workers have equal weight, regardless of amount bonded
pub const WORKER_WEIGHT: nonempty::Uint256 = nonempty::Uint256::one();

impl From<WeightedWorker> for Participant {
    fn from(worker: WeightedWorker) -> Participant {
        Self {
            weight: worker.weight,
            address: worker.worker_info.address,
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum AuthorizationState {
    NotAuthorized,
    Authorized,
    Jailed,
}

type ChainNames = HashSet<ChainName>;
type ServiceName = str;
type WorkerAddress = Addr;

pub const SERVICES: Map<&ServiceName, Service> = Map::new("services");
pub const WORKERS_PER_CHAIN: Map<(&ServiceName, &ChainName, &WorkerAddress), ()> =
    Map::new("workers_per_chain");
pub const CHAINS_PER_WORKER: Map<(&ServiceName, &WorkerAddress), ChainNames> =
    Map::new("chains_per_worker");
pub const WORKERS: Map<(&ServiceName, &WorkerAddress), Worker> = Map::new("workers");

pub fn register_chains_support(
    storage: &mut dyn Storage,
    service_name: String,
    chains: Vec<ChainName>,
    worker: WorkerAddress,
) -> Result<(), ContractError> {
    CHAINS_PER_WORKER.update(storage, (&service_name, &worker), |current_chains| {
        let mut current_chains = current_chains.unwrap_or_default();
        current_chains.extend(chains.iter().cloned());
        Ok::<HashSet<ChainName>, ContractError>(current_chains)
    })?;

    for chain in chains.iter() {
        WORKERS_PER_CHAIN.save(storage, (&service_name, chain, &worker), &())?;
    }

    Ok(())
}

pub fn may_load_chains_per_worker(
    storage: &dyn Storage,
    service_name: String,
    worker_address: WorkerAddress,
) -> Result<HashSet<ChainName>, ContractError> {
    CHAINS_PER_WORKER
        .may_load(storage, (&service_name, &worker_address))?
        .ok_or(ContractError::WorkerNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::mock_dependencies;
    use std::{str::FromStr, vec};

    #[test]
    fn register_single_worker_chain_single_call_success() {
        let mut deps = mock_dependencies();
        let worker = Addr::unchecked("worker");
        let service_name = "validators";
        let chain_name = ChainName::from_str("ethereum").unwrap();
        let chains = vec![chain_name.clone()];
        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            chains,
            worker.clone()
        )
        .is_ok());

        let worker_chains =
            may_load_chains_per_worker(deps.as_mut().storage, service_name.into(), worker).unwrap();
        assert!(worker_chains.contains(&chain_name));
    }

    #[test]
    fn register_multiple_worker_chains_single_call_success() {
        let mut deps = mock_dependencies();
        let worker = Addr::unchecked("worker");
        let service_name = "validators";
        let chain_names = vec![
            ChainName::from_str("ethereum").unwrap(),
            ChainName::from_str("cosmos").unwrap(),
        ];

        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            chain_names.clone(),
            worker.clone()
        )
        .is_ok());

        let worker_chains =
            may_load_chains_per_worker(deps.as_mut().storage, service_name.into(), worker).unwrap();

        for chain_name in chain_names {
            assert!(worker_chains.contains(&chain_name));
        }
    }

    #[test]
    fn register_multiple_worker_chains_multiple_calls_success() {
        let mut deps = mock_dependencies();
        let worker = Addr::unchecked("worker");
        let service_name = "validators";

        let first_chain_name = ChainName::from_str("ethereum").unwrap();
        let first_chains_vector = vec![first_chain_name.clone()];
        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            first_chains_vector,
            worker.clone()
        )
        .is_ok());

        let second_chain_name = ChainName::from_str("cosmos").unwrap();
        let second_chains_vector = vec![second_chain_name.clone()];
        assert!(register_chains_support(
            deps.as_mut().storage,
            service_name.into(),
            second_chains_vector,
            worker.clone()
        )
        .is_ok());

        let worker_chains =
            may_load_chains_per_worker(deps.as_mut().storage, service_name.into(), worker).unwrap();

        assert!(worker_chains.contains(&first_chain_name));
        assert!(worker_chains.contains(&second_chain_name));
    }

    #[test]
    fn get_unregistered_worker_chains_fails() {
        let mut deps = mock_dependencies();
        let worker = Addr::unchecked("worker");
        let service_name = "validators";

        let err = may_load_chains_per_worker(deps.as_mut().storage, service_name.into(), worker)
            .unwrap_err();
        assert!(matches!(err, ContractError::WorkerNotFound));
    }

    #[test]
    fn test_bonded_add_bond() {
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: BondingState::Bonded {
                amount: Uint128::from(100u32),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.add_bond(Uint128::from(200u32));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Bonded {
                amount: Uint128::from(300u32)
            }
        );
    }

    #[test]
    fn test_requested_unbonding_add_bond() {
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.add_bond(Uint128::from(200u32));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Bonded {
                amount: Uint128::from(300u32)
            }
        );
    }

    #[test]
    fn test_unbonding_add_bond() {
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: BondingState::Unbonding {
                amount: Uint128::from(100u32),
                unbonded_at: Timestamp::from_nanos(0),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.add_bond(Uint128::from(200u32));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Bonded {
                amount: Uint128::from(300u32)
            }
        );
    }

    #[test]
    fn test_unbonded_add_bond() {
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: BondingState::Unbonded,
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.add_bond(Uint128::from(200u32));
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Bonded {
                amount: Uint128::from(200u32)
            }
        );
    }

    #[test]
    fn test_zero_bond() {
        let bonding_state = BondingState::Unbonded;

        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.add_bond(Uint128::from(0u32));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state)
        );
    }

    #[test]
    fn test_bonded_unbond() {
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: BondingState::Bonded {
                amount: Uint128::from(100u32),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let unbonded_at = Timestamp::from_nanos(0);
        let res = worker.unbond(true, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Unbonding {
                amount: Uint128::from(100u32),
                unbonded_at
            }
        );
    }

    #[test]
    fn test_bonded_unbond_cant_unbond() {
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: BondingState::Bonded {
                amount: Uint128::from(100u32),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let unbonded_at = Timestamp::from_nanos(0);
        let res = worker.unbond(false, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32)
            }
        );
    }

    #[test]
    fn test_requested_unbonding_unbond() {
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let unbonded_at = Timestamp::from_nanos(0);
        let res = worker.unbond(true, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::Unbonding {
                amount: Uint128::from(100u32),
                unbonded_at
            }
        );
    }

    #[test]
    fn test_requested_unbonding_cant_unbond() {
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32),
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let unbonded_at = Timestamp::from_nanos(0);
        let res = worker.unbond(false, unbonded_at);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().bonding_state,
            BondingState::RequestedUnbonding {
                amount: Uint128::from(100u32)
            }
        );
    }

    #[test]
    fn test_unbonding_unbond() {
        let bonding_state = BondingState::Unbonding {
            amount: Uint128::from(100u32),
            unbonded_at: Timestamp::from_nanos(0),
        };

        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.clone().unbond(true, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = worker.unbond(false, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );
    }

    #[test]
    fn test_unbonded_unbond() {
        let bonding_state = BondingState::Unbonded;

        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.clone().unbond(true, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = worker.unbond(false, Timestamp::from_nanos(2));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );
    }

    #[test]
    fn test_bonded_claim_stake() {
        let bonding_state = BondingState::Bonded {
            amount: Uint128::from(100u32),
        };
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.clone().claim_stake(Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = worker.claim_stake(Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );
    }

    #[test]
    fn test_requested_unbonding_claim_stake() {
        let bonding_state = BondingState::RequestedUnbonding {
            amount: Uint128::from(100u32),
        };
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.clone().claim_stake(Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = worker.claim_stake(Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );
    }

    #[test]
    fn test_unbonding_claim_stake() {
        let bonding_state = BondingState::Unbonding {
            amount: Uint128::from(100u32),
            unbonded_at: Timestamp::from_nanos(0),
        };
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.clone().claim_stake(Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = worker.claim_stake(Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_ok());

        let (worker, amount) = res.unwrap();
        assert_eq!(
            (worker.bonding_state, amount),
            (BondingState::Unbonded, Uint128::from(100u32))
        );
    }

    #[test]
    fn test_unbonded_claim_stake() {
        let bonding_state = BondingState::Unbonded;
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: bonding_state.clone(),
            authorization_state: AuthorizationState::Authorized,
            service_name: "validators".to_string(),
        };

        let res = worker.clone().claim_stake(Timestamp::from_seconds(60), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );

        let res = worker.claim_stake(Timestamp::from_seconds(60 * 60 * 24), 1);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ContractError::InvalidBondingState(bonding_state.clone())
        );
    }

    #[test]
    fn jailed_worker_cannot_unbond() {
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: BondingState::Bonded {
                amount: Uint128::from(100u32),
            },
            authorization_state: AuthorizationState::Jailed,
            service_name: "validators".to_string(),
        };

        let res = worker.unbond(true, Timestamp::from_nanos(0));
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ContractError::WorkerJailed);
    }

    #[test]
    fn jailed_worker_cannot_claim_stake() {
        let worker = Worker {
            address: Addr::unchecked("worker"),
            bonding_state: BondingState::Unbonding {
                amount: Uint128::from(100u32),
                unbonded_at: Timestamp::from_nanos(0),
            },
            authorization_state: AuthorizationState::Jailed,
            service_name: "validators".to_string(),
        };

        let res = worker.claim_stake(Timestamp::from_nanos(1), 0);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ContractError::WorkerJailed);
    }
}

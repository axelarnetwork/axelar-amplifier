#![allow(deprecated)]

use std::collections::HashMap;
use std::marker::PhantomData;
use std::u64;

use axelar_wasm_std::error::ContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, Storage, Uint128};
use cw_storage_plus::{Item, KeyDeserialize, Map};
use router_api::ChainName;

use crate::contract::CONTRACT_NAME;
use crate::state::{self, EpochTally, ParamsSnapshot, PoolId, TallyId};

const BASE_VERSION: &str = "1.0.0";

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    migrate_params(storage)?;
    Ok(())
}

fn migrate_params(storage: &mut dyn Storage) -> Result<(), ContractError> {
    let params = PARAMS.load(storage)?;
    let funded_pools = get_all_pools(storage)?;

    for pool in funded_pools.values() {
        state::save_rewards_pool(
            storage,
            &state::RewardsPool {
                params: params.to_owned(),
                id: pool.id.to_owned(),
                balance: pool.balance,
            },
        )?;
    }

    let tallied_pools = get_pool_ids_from_tallies(storage)?;
    for pool in tallied_pools {
        if funded_pools.contains_key(&pool) {
            continue;
        }
        state::save_rewards_pool(
            storage,
            &state::RewardsPool {
                params: params.to_owned(),
                id: pool,
                balance: Uint128::zero(),
            },
        )?;
    }
    PARAMS.remove(storage);

    Ok(())
}

const POOLS: Map<PoolId, RewardsPool> = Map::new("pools");

const TALLIES: Map<TallyId, EpochTally> = Map::new("tallies");

// This will only return pools that were funded
fn get_all_pools(storage: &mut dyn Storage) -> Result<HashMap<PoolId, RewardsPool>, ContractError> {
    POOLS
        .range(storage, None, None, Order::Ascending)
        .map(|res| res.map_err(|err| err.into()))
        .collect::<Result<HashMap<_, _>, _>>()
}

// Pools can have active tallies without being funded, or having an object in the POOLS map
fn get_pool_ids_from_tallies(storage: &mut dyn Storage) -> Result<Vec<PoolId>, ContractError> {
    let mut pool_ids: Vec<PoolId> = vec![];
    let mut lower_bound = None;
    loop {
        let tallies: Vec<_> = TALLIES
            .range_raw(storage, lower_bound, None, Order::Ascending)
            .take(1)
            .collect::<Result<Vec<_>, _>>()?;
        match tallies.as_slice() {
            [] => {
                break;
            }
            [(tally_id, _)] => {
                // cw_storage_plus v1.2.0 has a known bug where certain key types are not decoded correctly
                // However, treating the key as a 3 element tuple works to decode the individual fields, and then
                // we can recreate the pool id
                let (chain_name, contract, _) =
                    <(ChainName, Addr, u64)>::from_vec(tally_id.to_owned())?;
                let pool_id = PoolId {
                    chain_name,
                    contract,
                };
                pool_ids.push(pool_id.clone());
                lower_bound = Some(cw_storage_plus::Bound::Exclusive((
                    TallyId {
                        pool_id,
                        epoch_num: u64::MAX,
                    },
                    PhantomData,
                )));
            }
            _ => panic!("take yielded more than one"),
        };
    }
    Ok(pool_ids)
}

#[deprecated(since = "1.0.0", note = "only used during migration")]
const PARAMS: Item<ParamsSnapshot> = Item::new("params");

#[cw_serde]
#[deprecated(since = "1.0.0", note = "only used during migration")]
struct RewardsPool {
    pub id: PoolId,
    pub balance: Uint128,
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use axelar_wasm_std::permission_control;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response, Uint128};

    use super::{RewardsPool, PARAMS, POOLS, TALLIES};
    use crate::contract::migrations::v1_0_0;
    use crate::contract::CONTRACT_NAME;
    use crate::msg::{InstantiateMsg, Params};
    use crate::state::{self, Config, Epoch, EpochTally, ParamsSnapshot, PoolId, TallyId, CONFIG};

    #[test]
    fn migrate_rewards_pools() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut(), "denom");

        let test_pools = vec![
            RewardsPool {
                id: PoolId {
                    chain_name: "mock-chain".parse().unwrap(),
                    contract: Addr::unchecked("contract-1"),
                },
                balance: Uint128::from(250u128),
            },
            RewardsPool {
                id: PoolId {
                    chain_name: "mock-chain-2".parse().unwrap(),
                    contract: Addr::unchecked("contract-2"),
                },
                balance: Uint128::from(100u128),
            },
        ];

        for pool in &test_pools {
            POOLS
                .save(deps.as_mut().storage, pool.id.to_owned(), pool)
                .unwrap();
        }

        let current_epoch = Epoch {
            epoch_num: 10,
            block_height_started: 100,
        };
        let test_tally_ids = [
            TallyId {
                pool_id: PoolId {
                    chain_name: "mock-chain".parse().unwrap(),
                    contract: Addr::unchecked("contract-1"),
                },
                epoch_num: current_epoch.epoch_num,
            },
            TallyId {
                pool_id: PoolId {
                    chain_name: "mock-chain-3".parse().unwrap(),
                    contract: Addr::unchecked("contract-3"),
                },
                epoch_num: current_epoch.epoch_num,
            },
            TallyId {
                pool_id: PoolId {
                    chain_name: "mock-chain-4".parse().unwrap(),
                    contract: Addr::unchecked("contract-4"),
                },
                epoch_num: current_epoch.epoch_num,
            },
        ];

        let params = PARAMS.load(deps.as_mut().storage).unwrap();
        let mut test_tallies: Vec<(&TallyId, EpochTally)> = test_tally_ids
            .iter()
            .map(|tally_id| {
                (
                    tally_id,
                    EpochTally {
                        pool_id: tally_id.pool_id.clone(),
                        event_count: 1,
                        participation: HashMap::new(),
                        epoch: current_epoch.clone(),
                        params: params.params.clone(),
                    },
                )
            })
            .collect();
        let mut test_tallies_2 = test_tallies.clone();
        test_tallies_2
            .iter_mut()
            .for_each(|(_, tally)| tally.epoch.epoch_num += 1);
        test_tallies.append(&mut test_tallies_2);

        for tally in &test_tallies {
            TALLIES
                .save(deps.as_mut().storage, tally.0.to_owned(), &tally.1)
                .unwrap();
        }

        v1_0_0::migrate(deps.as_mut().storage).unwrap();

        for pool in &test_pools {
            let new_pool =
                state::load_rewards_pool(deps.as_mut().storage, pool.id.to_owned()).unwrap();
            assert_eq!(
                new_pool,
                state::RewardsPool {
                    id: pool.id.to_owned(),
                    balance: pool.balance,
                    params: params.clone()
                }
            );
        }

        for (tally_id, _) in &test_tallies {
            if test_pools.iter().any(|pool| pool.id == tally_id.pool_id) {
                continue;
            }
            let new_pool =
                state::load_rewards_pool(deps.as_mut().storage, tally_id.pool_id.to_owned())
                    .unwrap();
            assert_eq!(
                new_pool,
                state::RewardsPool {
                    id: tally_id.pool_id.to_owned(),
                    balance: Uint128::zero(),
                    params: params.clone()
                }
            );
        }
    }

    #[test]
    fn migrate_checks_contract_version() {
        let mut deps = mock_dependencies();
        instantiate_contract(deps.as_mut(), "denom");
        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, "something wrong").unwrap();

        assert!(v1_0_0::migrate(deps.as_mut().storage).is_err());

        cw2::set_contract_version(deps.as_mut().storage, CONTRACT_NAME, v1_0_0::BASE_VERSION)
            .unwrap();

        assert!(v1_0_0::migrate(deps.as_mut().storage).is_ok());
    }

    #[deprecated(since = "0.4.0", note = "only used during migration tests")]
    pub fn instantiate_contract(deps: DepsMut, denom: impl Into<String>) {
        let msg = InstantiateMsg {
            governance_address: "governance".to_string(),
            rewards_denom: denom.into(),
        };
        instantiate(deps, mock_env(), mock_info("anyone", &[]), msg).unwrap();
    }

    #[deprecated(since = "0.4.0", note = "only used during migration tests")]
    fn instantiate(
        deps: DepsMut,
        env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        cw2::set_contract_version(deps.storage, CONTRACT_NAME, v1_0_0::BASE_VERSION)?;

        let governance = deps.api.addr_validate(&msg.governance_address)?;
        permission_control::set_governance(deps.storage, &governance)?;

        CONFIG.save(
            deps.storage,
            &Config {
                rewards_denom: msg.rewards_denom,
            },
        )?;

        let params = Params {
            epoch_duration: 100u64.try_into().unwrap(),
            rewards_per_epoch: 1000u128.try_into().unwrap(),
            participation_threshold: (1, 2).try_into().unwrap(),
        };
        PARAMS.save(
            deps.storage,
            &ParamsSnapshot {
                params,
                created_at: Epoch {
                    epoch_num: 0,
                    block_height_started: env.block.height,
                },
            },
        )?;

        Ok(Response::new())
    }
}

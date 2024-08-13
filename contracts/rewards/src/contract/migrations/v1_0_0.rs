#![allow(deprecated)]

use axelar_wasm_std::error::ContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Order, Storage, Uint128};
use cw_storage_plus::{Item, Map};

use crate::contract::CONTRACT_NAME;
use crate::state::{self, ParamsSnapshot, PoolId};

const BASE_VERSION: &str = "1.0.0";

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    cw2::assert_contract_version(storage, CONTRACT_NAME, BASE_VERSION)?;

    migrate_params(storage)?;
    Ok(())
}

fn migrate_params(storage: &mut dyn Storage) -> Result<(), ContractError> {
    let params = PARAMS.load(storage)?;
    let pools = get_all_pools(storage)?;

    for pool in pools {
        state::save_rewards_pool(
            storage,
            &state::RewardsPool {
                params: params.to_owned(),
                id: pool.id,
                balance: pool.balance,
            },
        )?;
    }
    PARAMS.remove(storage);

    Ok(())
}

const POOLS: Map<PoolId, RewardsPool> = Map::new("pools");

fn get_all_pools(storage: &mut dyn Storage) -> Result<Vec<RewardsPool>, ContractError> {
    POOLS
        .range(storage, None, None, Order::Ascending)
        .map(|res| res.map(|(_, pool)| pool).map_err(|err| err.into()))
        .collect::<Result<Vec<_>, _>>()
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
    use axelar_wasm_std::permission_control;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Addr, DepsMut, Env, MessageInfo, Response, Uint128};

    use super::{RewardsPool, PARAMS, POOLS};
    use crate::contract::migrations::v1_0_0;
    use crate::contract::CONTRACT_NAME;
    use crate::msg::{InstantiateMsg, Params};
    use crate::state::{self, Config, Epoch, ParamsSnapshot, PoolId, CONFIG};

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
        let params = PARAMS.load(deps.as_mut().storage).unwrap();

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

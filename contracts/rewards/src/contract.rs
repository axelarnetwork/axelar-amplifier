use axelar_wasm_std::nonempty;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Response,
};
use error_stack::ResultExt;
use itertools::Itertools;

use crate::{
    error::ContractError,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{self, Config, Epoch, ParamsSnapshot, PoolId, CONFIG, PARAMS},
};

mod execute;
mod query;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let governance = deps.api.addr_validate(&msg.governance_address)?;

    CONFIG.save(
        deps.storage,
        &Config {
            governance,
            rewards_denom: msg.rewards_denom,
        },
    )?;

    PARAMS.save(
        deps.storage,
        &ParamsSnapshot {
            params: msg.params,
            created_at: Epoch {
                epoch_num: 0,
                block_height_started: env.block.height,
            },
        },
    )?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::RecordParticipation {
            chain_name,
            event_id,
            worker_address,
        } => {
            let worker_address = deps.api.addr_validate(&worker_address)?;
            let pool_id = PoolId {
                chain_name,
                contract: info.sender.clone(),
            };
            execute::record_participation(
                deps.storage,
                event_id,
                worker_address,
                pool_id,
                env.block.height,
            )
            .map_err(axelar_wasm_std::ContractError::from)?;

            Ok(Response::new())
        }
        ExecuteMsg::AddRewards { pool_id } => {
            deps.api.addr_validate(pool_id.contract.as_str())?;

            let amount = info
                .funds
                .iter()
                .find(|coin| coin.denom == state::load_config(deps.storage).rewards_denom)
                .filter(|_| info.funds.len() == 1) // filter here to make sure expected denom is the only one attached to this message, and other funds aren't silently swallowed
                .ok_or(ContractError::WrongDenom)?
                .amount;

            execute::add_rewards(
                deps.storage,
                pool_id,
                nonempty::Uint128::try_from(amount).change_context(ContractError::ZeroRewards)?,
            )?;

            Ok(Response::new())
        }
        ExecuteMsg::DistributeRewards {
            pool_id,
            epoch_count,
        } => {
            deps.api.addr_validate(pool_id.contract.as_str())?;

            let rewards =
                execute::distribute_rewards(deps.storage, pool_id, env.block.height, epoch_count)
                    .map_err(axelar_wasm_std::ContractError::from)?;

            let msgs = rewards
                .into_iter()
                .sorted()
                .map(|(addr, amount)| BankMsg::Send {
                    to_address: addr.into(),
                    amount: vec![Coin {
                        denom: state::load_config(deps.storage).rewards_denom.clone(),
                        amount,
                    }],
                });

            Ok(Response::new().add_messages(msgs))
        }
        ExecuteMsg::UpdateParams { params } => {
            execute::update_params(deps.storage, params, env.block.height, info.sender)?;

            Ok(Response::new())
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::ContractError> {
    match msg {
        QueryMsg::RewardsPool { pool_id } => {
            let pool = query::rewards_pool(deps.storage, pool_id, env.block.height)?;
            to_json_binary(&pool)
                .change_context(ContractError::SerializeResponse)
                .map_err(axelar_wasm_std::ContractError::from)
        }
    }
}

#[cfg(test)]
mod tests {
    use connection_router_api::ChainName;
    use cosmwasm_std::{coins, Addr, BlockInfo, Uint128};
    use cw_multi_test::{App, ContractWrapper, Executor};

    use crate::msg::{ExecuteMsg, InstantiateMsg, Params, QueryMsg, RewardsPool};
    use crate::state::PoolId;

    use super::{execute, instantiate, query};

    /// Tests that the contract entry points (instantiate, query and execute) work as expected.
    /// Instantiates the contract and calls each of the 4 ExecuteMsg variants.
    /// Adds rewards to the pool, updates the rewards params, records some participation
    /// events and then distributes the rewards.
    #[test]
    fn test_rewards_flow() {
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        let user = Addr::unchecked("user");
        let worker = Addr::unchecked("worker");
        let worker_contract = Addr::unchecked("worker contract");

        const AXL_DENOMINATION: &str = "uaxl";
        let mut app = App::new(|router, _, storage| {
            router
                .bank
                .init_balance(storage, &user, coins(100000, AXL_DENOMINATION))
                .unwrap()
        });
        let code = ContractWrapper::new(execute, instantiate, query);
        let code_id = app.store_code(Box::new(code));

        let governance_address = Addr::unchecked("governance");
        let initial_params = Params {
            epoch_duration: 10u64.try_into().unwrap(),
            rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
            participation_threshold: (1, 2).try_into().unwrap(),
        };
        let contract_address = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("router"),
                &InstantiateMsg {
                    governance_address: governance_address.to_string(),
                    rewards_denom: AXL_DENOMINATION.to_string(),
                    params: initial_params.clone(),
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let pool_id = PoolId {
            chain_name: chain_name.clone(),
            contract: worker_contract.clone(),
        };

        let rewards = 200;
        let res = app.execute_contract(
            user.clone(),
            contract_address.clone(),
            &ExecuteMsg::AddRewards {
                pool_id: pool_id.clone(),
            },
            &coins(rewards, AXL_DENOMINATION),
        );
        assert!(res.is_ok());

        let updated_params = Params {
            rewards_per_epoch: Uint128::from(150u128).try_into().unwrap(),
            ..initial_params
        };
        let res = app.execute_contract(
            governance_address,
            contract_address.clone(),
            &ExecuteMsg::UpdateParams {
                params: updated_params.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

        let res = app.execute_contract(
            worker_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some event".to_string().try_into().unwrap(),
                worker_address: worker.to_string(),
            },
            &[],
        );
        assert!(res.is_ok());

        let res = app.execute_contract(
            worker_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some other event".to_string().try_into().unwrap(),
                worker_address: worker.to_string(),
            },
            &[],
        );
        assert!(res.is_ok());

        // check the rewards pool
        let res: RewardsPool = app
            .wrap()
            .query_wasm_smart(contract_address.clone(), &QueryMsg::RewardsPool { pool_id })
            .unwrap();
        assert_eq!(
            res,
            RewardsPool {
                balance: rewards.into(),
                epoch_duration: updated_params.epoch_duration.into(),
                rewards_per_epoch: updated_params.rewards_per_epoch.into(),
                current_epoch_num: 0u64.into(),
                last_distribution_epoch: None
            }
        );

        // need to change the block height, so we can claim rewards
        let old_height = app.block_info().height;
        app.set_block(BlockInfo {
            height: old_height + u64::from(initial_params.epoch_duration) * 2,
            ..app.block_info()
        });

        let res = app.execute_contract(
            user,
            contract_address.clone(),
            &ExecuteMsg::DistributeRewards {
                pool_id: PoolId {
                    chain_name: chain_name.clone(),
                    contract: worker_contract.clone(),
                },
                epoch_count: None,
            },
            &[],
        );
        assert!(res.is_ok());

        // worker should have been sent the appropriate rewards
        let balance = app.wrap().query_balance(worker, AXL_DENOMINATION).unwrap();
        assert_eq!(balance.amount, Uint128::from(150u128));
    }
}

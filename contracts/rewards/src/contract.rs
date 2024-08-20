use axelar_wasm_std::{address, nonempty, permission_control};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, BankMsg, Binary, Coin, Deps, DepsMut, Empty, Env, MessageInfo, Response,
};
use error_stack::ResultExt;
use itertools::Itertools;

use crate::error::ContractError;
use crate::events;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{self, Config, PoolId, CONFIG};

mod execute;
mod migrations;
mod query;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    migrations::v1_0_0::migrate(deps.storage)?;

    // any version checks should be done before here

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;
    permission_control::set_governance(deps.storage, &governance)?;

    CONFIG.save(
        deps.storage,
        &Config {
            rewards_denom: msg.rewards_denom,
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
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::RecordParticipation {
            chain_name,
            event_id,
            verifier_address,
        } => {
            let verifier_address = address::validate_cosmwasm_address(deps.api, &verifier_address)?;
            let pool_id = PoolId {
                chain_name,
                contract: info.sender,
            };
            execute::record_participation(
                deps.storage,
                event_id,
                verifier_address,
                pool_id,
                env.block.height,
            )?;

            Ok(Response::new())
        }
        ExecuteMsg::AddRewards { pool_id } => {
            address::validate_cosmwasm_address(deps.api, pool_id.contract.as_str())?;

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
            address::validate_cosmwasm_address(deps.api, pool_id.contract.as_str())?;

            let rewards_distribution = execute::distribute_rewards(
                deps.storage,
                pool_id.clone(),
                env.block.height,
                epoch_count,
            )?;

            let msgs = rewards_distribution
                .rewards
                .clone()
                .into_iter()
                .sorted()
                .map(|(addr, amount)| BankMsg::Send {
                    to_address: addr.into(),
                    amount: vec![Coin {
                        denom: state::load_config(deps.storage).rewards_denom.clone(),
                        amount,
                    }],
                });

            Ok(Response::new()
                .add_messages(msgs)
                .add_event(events::Event::from(rewards_distribution).into()))
        }
        ExecuteMsg::UpdatePoolParams { params, pool_id } => {
            execute::update_pool_params(deps.storage, &pool_id, params, env.block.height)?;

            Ok(Response::new())
        }
        ExecuteMsg::CreatePool { params, pool_id } => {
            execute::create_pool(deps.storage, params, env.block.height, &pool_id)?;
            Ok(Response::new())
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::RewardsPool { pool_id } => {
            let pool = query::rewards_pool(deps.storage, pool_id, env.block.height)?;
            to_json_binary(&pool)
                .change_context(ContractError::SerializeResponse)
                .map_err(axelar_wasm_std::error::ContractError::from)
        }
        QueryMsg::VerifierParticipation { pool_id, epoch_num } => {
            let tally = query::participation(deps.storage, pool_id, epoch_num, env.block.height)?;
            to_json_binary(&tally)
                .change_context(ContractError::SerializeResponse)
                .map_err(axelar_wasm_std::error::ContractError::from)
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coins, Addr, BlockInfo, Uint128};
    use cw_multi_test::{App, ContractWrapper, Executor};
    use router_api::ChainName;

    use super::*;
    use crate::msg::{ExecuteMsg, InstantiateMsg, Params, QueryMsg, RewardsPool};
    use crate::state::PoolId;

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = mock_dependencies();

        #[allow(deprecated)]
        migrations::v1_0_0::tests::instantiate_contract(deps.as_mut(), "denom");

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    /// Tests that the contract entry points (instantiate, query and execute) work as expected.
    /// Instantiates the contract and calls each of the 4 ExecuteMsg variants.
    /// Adds rewards to the pool, updates the rewards params, records some participation
    /// events and then distributes the rewards.
    #[test]
    fn test_rewards_flow() {
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        let user = Addr::unchecked("user");
        let verifier = Addr::unchecked("verifier");
        let pool_contract = Addr::unchecked("pool_contract");

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
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let pool_id = PoolId {
            chain_name: chain_name.clone(),
            contract: pool_contract.clone(),
        };

        let res = app.execute_contract(
            governance_address.clone(),
            contract_address.clone(),
            &ExecuteMsg::CreatePool {
                params: initial_params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

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
            &ExecuteMsg::UpdatePoolParams {
                params: updated_params.clone(),
                pool_id: pool_id.clone(),
            },
            &[],
        );
        assert!(res.is_ok());

        let res = app.execute_contract(
            pool_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some event".try_into().unwrap(),
                verifier_address: verifier.to_string(),
            },
            &[],
        );
        assert!(res.is_ok());

        let res = app.execute_contract(
            pool_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
                chain_name: chain_name.clone(),
                event_id: "some other event".try_into().unwrap(),
                verifier_address: verifier.to_string(),
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
                    contract: pool_contract.clone(),
                },
                epoch_count: None,
            },
            &[],
        );
        assert!(res.is_ok());

        // verifier should have been sent the appropriate rewards
        let balance = app
            .wrap()
            .query_balance(verifier, AXL_DENOMINATION)
            .unwrap();
        assert_eq!(balance.amount, Uint128::from(150u128));
    }
}

use crate::{
    contract::execute::Contract,
    error::ContractError,
    msg::{ExecuteMsg, InstantiateMsg},
    state::{Config, Epoch, StoredParams, CONFIG, PARAMS},
};
use axelar_wasm_std::nonempty;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{BankMsg, Coin, DepsMut, Env, MessageInfo, Response};
use error_stack::ResultExt;

use itertools::Itertools;

mod execute;

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
        &StoredParams {
            params: msg.params,
            last_updated: Epoch {
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
            event_id,
            worker_address,
        } => {
            let worker_address = deps.api.addr_validate(&worker_address)?;
            Contract::new(deps)
                .record_participation(event_id, worker_address, info.sender, env.block.height)
                .map_err(axelar_wasm_std::ContractError::from)?;

            Ok(Response::new())
        }
        ExecuteMsg::AddRewards { contract_address } => {
            let contract_address = deps.api.addr_validate(&contract_address)?;
            let mut contract = Contract::new(deps);
            let amount = info
                .funds
                .iter()
                .find(|coin| coin.denom == contract.config.rewards_denom)
                .filter(|_| info.funds.len() == 1) // filter here to make sure expected denom is the only one attached to this message, and other funds aren't silently swallowed
                .ok_or(ContractError::WrongDenom)?
                .amount;

            contract.add_rewards(
                contract_address,
                nonempty::Uint128::try_from(amount).change_context(ContractError::ZeroRewards)?,
            )?;

            Ok(Response::new())
        }
        ExecuteMsg::DistributeRewards {
            contract_address,
            epoch_count,
        } => {
            let contract_address = deps.api.addr_validate(&contract_address)?;
            let mut contract = Contract::new(deps);
            let rewards = contract
                .distribute_rewards(contract_address, env.block.height, epoch_count)
                .map_err(axelar_wasm_std::ContractError::from)?;

            let msgs = rewards
                .into_iter()
                .sorted()
                .map(|(addr, amount)| BankMsg::Send {
                    to_address: addr.into(),
                    amount: vec![Coin {
                        denom: contract.config.rewards_denom.clone(),
                        amount,
                    }],
                });

            Ok(Response::new().add_messages(msgs))
        }
        ExecuteMsg::UpdateParams { params } => {
            Contract::new(deps).update_params(params, env.block.height, info.sender)?;

            Ok(Response::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{coins, Addr, Binary, BlockInfo, Deps, Env, StdResult, Uint128};
    use cw_multi_test::{App, ContractWrapper, Executor};

    use crate::msg::{ExecuteMsg, InstantiateMsg, Params, QueryMsg};

    use super::{execute, instantiate};

    /// Tests that the contract entry points (instantiate and execute) work as expected.
    /// Instantiates the contract and calls each of the 4 ExecuteMsg variants.
    /// Adds rewards to the contract, updates the rewards params, records some participation
    /// events and then distributes the rewards.
    #[test]
    fn test_rewards_flow() {
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
        let code = ContractWrapper::new(
            execute,
            instantiate,
            |_deps: Deps, _env: Env, _msg: QueryMsg| -> StdResult<Binary> { todo!() },
        );
        let code_id = app.store_code(Box::new(code));

        let governance_address = Addr::unchecked("governance");
        let initial_params = Params {
            epoch_duration: 10u64.try_into().unwrap(),
            rewards_per_epoch: Uint128::one().try_into().unwrap(),
            participation_threshold: (1, 2).try_into().unwrap(),
        };
        let contract_address = app
            .instantiate_contract(
                code_id,
                Addr::unchecked("router"),
                &InstantiateMsg {
                    governance_address: governance_address.to_string(),
                    rewards_denom: AXL_DENOMINATION.to_string(),
                    params: Params {
                        epoch_duration: 10u64.try_into().unwrap(),
                        rewards_per_epoch: Uint128::from(100u128).try_into().unwrap(),
                        participation_threshold: (1, 2).try_into().unwrap(),
                    },
                },
                &[],
                "Contract",
                None,
            )
            .unwrap();

        let res = app.execute_contract(
            user.clone(),
            contract_address.clone(),
            &ExecuteMsg::AddRewards {
                contract_address: worker_contract.to_string(),
            },
            &coins(200, AXL_DENOMINATION),
        );
        assert!(res.is_ok());

        let res = app.execute_contract(
            governance_address,
            contract_address.clone(),
            &ExecuteMsg::UpdateParams {
                params: Params {
                    rewards_per_epoch: Uint128::from(150u128).try_into().unwrap(),
                    ..initial_params
                },
            },
            &[],
        );
        assert!(res.is_ok());

        let res = app.execute_contract(
            worker_contract.clone(),
            contract_address.clone(),
            &ExecuteMsg::RecordParticipation {
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
                event_id: "some other event".to_string().try_into().unwrap(),
                worker_address: worker.to_string(),
            },
            &[],
        );
        assert!(res.is_ok());

        // need to change the block height so we can claim rewards
        let old_height = app.block_info().height;
        app.set_block(BlockInfo {
            height: old_height + u64::from(initial_params.epoch_duration) * 2,
            ..app.block_info()
        });

        let res = app.execute_contract(
            user,
            contract_address.clone(),
            &ExecuteMsg::DistributeRewards {
                contract_address: worker_contract.to_string(),
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

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

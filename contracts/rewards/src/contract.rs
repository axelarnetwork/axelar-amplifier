use crate::{
    contract::execute::Contract,
    msg::{ExecuteMsg, InstantiateMsg},
    state::{Config, CONFIG},
};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, MessageInfo, Response};

mod execute;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
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

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let mut _contract = Contract::new(deps);
    match msg {
        ExecuteMsg::RecordParticipation { .. } => todo!(),
        ExecuteMsg::AddRewards { .. } => todo!(),
        ExecuteMsg::DistributeRewards { .. } => todo!(),
        ExecuteMsg::UpdateParams { .. } => todo!(),
    }
}

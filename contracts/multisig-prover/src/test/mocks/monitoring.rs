use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};

use monitoring::msg::QueryMsg;
use multisig::worker_set::WorkerSet;

pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: monitoring::msg::InstantiateMsg,
) -> Result<Response, StdError> {
    Ok(Response::default())
}

#[cw_serde]
pub enum ExecuteMsg {
    SetActiveVerifiers { next_worker_set: WorkerSet },
}

#[allow(unused_variables)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, StdError> {
    match msg {
        ExecuteMsg::SetActiveVerifiers { next_worker_set } => Ok(Response::new()),
    }
}

pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetActiveVerifiers { .. } => todo!(),
        QueryMsg::CheckWorkerCanUnbond { .. } => todo!(),
    }
}

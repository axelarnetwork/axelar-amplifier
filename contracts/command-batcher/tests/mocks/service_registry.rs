use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128,
};
use service_registry::{
    msg::{ActiveWorkers, ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{Worker, WorkerState},
};

use super::test_data;

pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, StdError> {
    Ok(Response::default())
}

pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, StdError> {
    Ok(Response::default())
}

pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetActiveWorkers { service_name } => {
            let workers = test_data::operators()
                .into_iter()
                .map(|op| Worker {
                    address: op.address,
                    stake: op.weight.try_into().unwrap(),
                    commission_rate: Uint128::zero(),
                    state: WorkerState::Active,
                    service_name: service_name.clone(),
                })
                .collect();

            to_binary(&ActiveWorkers { workers })
        }
    }
}

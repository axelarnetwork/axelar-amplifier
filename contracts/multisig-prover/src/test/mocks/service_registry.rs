use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use service_registry::{
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{AuthorizationState, BondingState, Worker},
};

use crate::test::test_data;

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
        QueryMsg::GetActiveWorkers {
            service_name,
            chain_name: _,
        } => {
            let workers = test_data::operators()
                .into_iter()
                .map(|op| Worker {
                    address: op.address,
                    bonding_state: BondingState::Bonded {
                        amount: op.weight.try_into().unwrap(),
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.clone(),
                })
                .collect::<Vec<Worker>>();

            to_binary(&workers)
        }
    }
}

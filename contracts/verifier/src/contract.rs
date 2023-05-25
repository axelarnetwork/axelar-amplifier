#[cfg(not(feature = "library"))]
use cosmwasm_std::{entry_point, DepsMut, Env, MessageInfo, Response};

use crate::{error::ContractError, msg::ExecuteMsg};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    todo!()
}

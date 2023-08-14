#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};

use crate::{
    error::ContractError,
    msg::ExecuteMsg,
    msg::{GetProofResponse, QueryMsg},
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ConstructProof { message_ids } => execute::construct_proof(message_ids),
    }
}

pub mod execute {
    use super::*;

    pub fn construct_proof(_message_ids: Vec<String>) -> Result<Response, ContractError> {
        todo!()
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetProof { proof_id } => to_binary(&query::get_proof(proof_id)?),
    }
}

pub mod query {
    use super::*;

    pub fn get_proof(_proof_id: String) -> StdResult<GetProofResponse> {
        todo!()
    }
}

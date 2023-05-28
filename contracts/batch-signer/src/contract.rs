#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult,
};

use crate::{
    error::ContractError,
    msg::QueryMsg,
    msg::{ExecuteMsg, InstantiateMsg},
    state::{Config, CONFIG},
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let gateway = deps.api.addr_validate(&msg.gateway_address)?;
    CONFIG.save(deps.storage, &Config { gateway })?;

    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ConstructProof { message_ids } => execute::construct_proof(message_ids),
        ExecuteMsg::SignProof {
            proof_id,
            signature,
        } => execute::sign_proof(proof_id, signature),
    }
}

pub mod execute {
    use super::*;

    pub fn construct_proof(_message_ids: Vec<String>) -> Result<Response, ContractError> {
        todo!()
    }

    pub fn sign_proof(_proof_id: String, _signature: HexBinary) -> Result<Response, ContractError> {
        todo!()
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}

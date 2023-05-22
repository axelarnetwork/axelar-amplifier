#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult,
};

use crate::{error::ContractError, msg::ExecuteMsg, msg::QueryMsg};

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

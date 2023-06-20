#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult, Uint64,
};

use crate::{
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    ContractError,
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    todo!()
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::StartSigningSession { sig_msg } => execute::start_signing_session(sig_msg),
        ExecuteMsg::SubmitSignature {
            multisig_session_id,
            signature,
        } => execute::submit_signature(multisig_session_id, signature),
    }
}

pub mod execute {
    use super::*;

    pub fn start_signing_session(_sig_msg: HexBinary) -> Result<Response, ContractError> {
        todo!()
    }

    pub fn submit_signature(
        _multisig_session_id: Uint64,
        _signature: HexBinary,
    ) -> Result<Response, ContractError> {
        todo!()
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetSigningSession {
            multisig_session_id,
        } => to_binary(&query::get_signing_session(multisig_session_id)?),
    }
}

pub mod query {
    use crate::msg::GetSigningSessionResponse;

    use super::*;

    pub fn get_signing_session(
        _multisig_session_id: Uint64,
    ) -> StdResult<GetSigningSessionResponse> {
        todo!()
    }
}

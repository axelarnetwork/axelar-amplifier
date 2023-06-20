#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult, Uint64,
};

use crate::{
    events::Event,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{get_current_key_set, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER},
    types::SigningSession,
    ContractError,
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    SIGNING_SESSION_COUNTER.save(deps.storage, &Uint64::zero())?;

    todo!()
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::StartSigningSession { sig_msg } => {
            execute::start_signing_session(deps, info, sig_msg)
        }
        ExecuteMsg::SubmitSignature {
            multisig_session_id,
            signature,
        } => execute::submit_signature(multisig_session_id, signature),
    }
}

pub mod execute {
    use super::*;

    pub fn start_signing_session(
        deps: DepsMut,
        info: MessageInfo,
        sig_msg: HexBinary,
    ) -> Result<Response, ContractError> {
        let key = get_current_key_set(deps.storage, info.sender)?;

        let sig_session_id = SIGNING_SESSION_COUNTER.update(
            deps.storage,
            |mut counter| -> Result<Uint64, ContractError> {
                counter += Uint64::one();
                Ok(counter)
            },
        )?;

        let signing_session = SigningSession::new(sig_session_id, key.id, sig_msg.clone());

        SIGNING_SESSIONS.save(deps.storage, sig_session_id.into(), &signing_session)?;

        let event = Event::SigningStarted {
            multisig_session_id: sig_session_id,
            key_set_id: key.id,
            pub_keys: key.pub_keys,
            sig_msg,
        };

        Ok(Response::new().add_event(event.into()))
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

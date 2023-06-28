#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint64,
};

use crate::{
    events::Event,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{get_current_key_set, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER},
    types::{Message, Signature, SigningSession},
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

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::StartSigningSession { msg } => {
            execute::start_signing_session(deps, info, msg.into())
        }
        ExecuteMsg::SubmitSignature { sig_id, signature } => {
            execute::submit_signature(sig_id, signature.into())
        }
    }
}

pub mod execute {
    use super::*;

    pub fn start_signing_session(
        deps: DepsMut,
        info: MessageInfo,
        msg: Message, // TODO: validate message before using this custom type
    ) -> Result<Response, ContractError> {
        let key = get_current_key_set(deps.storage, &info.sender)?;

        let sig_id = SIGNING_SESSION_COUNTER.update(
            deps.storage,
            |mut counter| -> Result<Uint64, ContractError> {
                counter += Uint64::one();
                Ok(counter)
            },
        )?;

        let signing_session = SigningSession::new(sig_id, key.id, msg.clone());

        SIGNING_SESSIONS.save(deps.storage, sig_id.into(), &signing_session)?;

        let event = Event::SigningStarted {
            sig_id,
            key_id: key.id,
            pub_keys: key.pub_keys,
            msg,
        };

        Ok(Response::new().add_event(event.into()))
    }

    pub fn submit_signature(
        _sig_id: Uint64,
        _signature: Signature, // TODO: validate signature before using this custom type
    ) -> Result<Response, ContractError> {
        todo!()
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetSigningSession { sig_id } => to_binary(&query::get_signing_session(sig_id)?),
    }
}

pub mod query {
    use crate::msg::GetSigningSessionResponse;

    use super::*;

    pub fn get_signing_session(_sig_id: Uint64) -> StdResult<GetSigningSessionResponse> {
        todo!()
    }
}

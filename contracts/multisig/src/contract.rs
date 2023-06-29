#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult,
    Uint64,
};

use axelar_wasm_std::Snapshot;
use std::collections::HashMap;

use crate::{
    events::Event,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{get_current_key, Config, CONFIG, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER},
    types::{Key, Message, Signature, SigningSession},
    ContractError,
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let admin = deps.api.addr_validate(&msg.admin_address)?;
    CONFIG.save(deps.storage, &Config { admin })?;
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
            execute::start_signing_session(deps, info, msg.try_into()?)
        }
        ExecuteMsg::SubmitSignature { sig_id, signature } => {
            execute::submit_signature(deps, info, sig_id, signature.try_into()?)
        }
        ExecuteMsg::SetKey {
            owner,
            snapshot,
            pub_keys,
        } => execute::set_key(deps, info, owner, snapshot, pub_keys),
    }
}

pub mod execute {
    use crate::{state::KEYS, types::PublicKey};

    use super::*;

    pub fn start_signing_session(
        deps: DepsMut,
        info: MessageInfo,
        msg: Message,
    ) -> Result<Response, ContractError> {
        let key = get_current_key(deps.storage, &info.sender)?;

        let sig_id = SIGNING_SESSION_COUNTER.update(
            deps.storage,
            |mut counter| -> Result<Uint64, ContractError> {
                counter += Uint64::one();
                Ok(counter)
            },
        )?;

        let signing_session = SigningSession::new(sig_id, key.clone().id, msg.clone());

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
        deps: DepsMut,
        info: MessageInfo,
        sig_id: Uint64,
        signature: Signature,
    ) -> Result<Response, ContractError> {
        let mut session = SIGNING_SESSIONS
            .load(deps.storage, sig_id.into())
            .map_err(|_| ContractError::SigningSessionNotFound { sig_id })?;

        session.add_signature(deps.storage, info.sender.clone().into(), signature.clone())?;

        let event = Event::SignatureSubmitted {
            sig_id,
            participant: info.sender,
            signature,
        };

        Ok(Response::new().add_event(event.into()))
    }

    // TODO: this will disappear once keygen and key rotation are introduced
    pub fn set_key(
        deps: DepsMut,
        info: MessageInfo,
        owner: Addr,
        snapshot: Snapshot,
        pub_keys: HashMap<String, HexBinary>,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;
        if config.admin != info.sender {
            return Err(ContractError::Unauthorized {});
        }

        let key = Key {
            id: owner.to_string(),
            snapshot,
            pub_keys: pub_keys
                .into_iter()
                .map(|(k, v)| (k, PublicKey::try_from(v).unwrap()))
                .collect(),
        };
        KEYS.save(deps.storage, owner.into(), &key)?;

        Ok(Response::default())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetSigningSession { sig_id } => {
            to_binary(&query::get_signing_session(deps, sig_id)?)
        }
    }
}

pub mod query {
    use crate::msg::GetSigningSessionResponse;

    use super::*;

    pub fn get_signing_session(deps: Deps, sig_id: Uint64) -> StdResult<GetSigningSessionResponse> {
        let session = SIGNING_SESSIONS.load(deps.storage, sig_id.into())?;

        let key = session.key(deps.storage)?;

        Ok(GetSigningSessionResponse {
            state: session.state,
            signatures: session.signatures,
            snapshot: key.snapshot,
        })
    }
}

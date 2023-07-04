#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult, Uint64,
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
        owner: String,
        snapshot: Snapshot,
        pub_keys: HashMap<String, HexBinary>,
    ) -> Result<Response, ContractError> {
        let owner = deps.api.addr_validate(&owner)?;

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

#[cfg(test)]
mod tests {
    use crate::{
        test::common::{build_snapshot, mock_message, mock_signers},
        types::MultisigState,
    };

    use super::*;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage},
        Addr, Empty, OwnedDeps,
    };

    use serde_json::from_str;

    const ADMIN: &str = "admin";
    const INSTANTIATOR: &str = "inst";
    const BATCHER: &str = "batcher";

    fn do_instantiate(deps: DepsMut) -> Result<Response, ContractError> {
        let info = mock_info(INSTANTIATOR, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {
            admin_address: ADMIN.to_string(),
        };

        instantiate(deps, env, info, msg)
    }

    fn do_set_key(deps: DepsMut) -> Result<Response, ContractError> {
        let info = mock_info(ADMIN, &[]);
        let env = mock_env();

        let signers = mock_signers();
        let pub_keys = signers
            .iter()
            .map(|signer| (signer.address.clone().to_string(), signer.pub_key.clone()))
            .collect::<HashMap<String, HexBinary>>();

        let msg = ExecuteMsg::SetKey {
            owner: BATCHER.to_string(),
            snapshot: build_snapshot(&signers),
            pub_keys,
        };

        execute(deps, env, info, msg)
    }

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();
        do_set_key(deps.as_mut()).unwrap();
        deps
    }

    // TODO: move to external crate?
    fn get_event_attribute<'a>(
        event: &'a cosmwasm_std::Event,
        attribute_name: &'a str,
    ) -> Option<&'a str> {
        event
            .attributes
            .iter()
            .find(|attribute| attribute.key == attribute_name)
            .map(|attribute| attribute.value.as_str())
    }

    #[test]
    fn test_instantiation() {
        let mut deps = mock_dependencies();

        let res = do_instantiate(deps.as_mut());
        assert!(res.is_ok());
        assert_eq!(0, res.unwrap().messages.len());

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        let session_counter = SIGNING_SESSION_COUNTER.load(deps.as_ref().storage).unwrap();

        assert_eq!(ADMIN.to_string(), config.admin);
        assert_eq!(session_counter, Uint64::zero());
    }

    #[test]
    fn test_start_signing_session() {
        let mut deps = setup();

        let message = mock_message();
        let msg = ExecuteMsg::StartSigningSession {
            msg: message.clone(),
        };
        let res = execute(deps.as_mut(), mock_env(), mock_info(BATCHER, &[]), msg);

        assert!(res.is_ok());

        let session = SIGNING_SESSIONS.load(deps.as_ref().storage, 1u64).unwrap();
        let key = get_current_key(deps.as_ref().storage, &Addr::unchecked(BATCHER)).unwrap();

        assert_eq!(session.id, Uint64::one());
        assert_eq!(session.key_id, key.id);
        assert_eq!(session.msg, message.clone().try_into().unwrap());
        assert!(session.signatures.is_empty());
        assert_eq!(session.state, MultisigState::Pending);

        let res = res.unwrap();
        assert_eq!(res.events.len(), 1);

        let event = res.events.get(0).unwrap();
        assert_eq!(event.ty, "signing_started".to_string());
        assert_eq!(
            get_event_attribute(event, "sig_id").unwrap(),
            Uint64::one().to_string()
        );
        assert_eq!(
            get_event_attribute(event, "key_id").unwrap(),
            session.key_id
        );
        assert_eq!(
            key.pub_keys,
            from_str(get_event_attribute(event, "pub_keys").unwrap()).unwrap()
        );
        assert_eq!(get_event_attribute(event, "msg").unwrap(), message.to_hex());
    }

    #[test]
    fn test_start_signing_session_wrong_sender() {
        let mut deps = setup();

        let message = mock_message();
        let msg = ExecuteMsg::StartSigningSession {
            msg: message.clone(),
        };

        let sender = "someone else";
        let res = execute(deps.as_mut(), mock_env(), mock_info(sender, &[]), msg);

        assert_eq!(
            res.unwrap_err(),
            ContractError::NoActiveKeyFound {
                owner: sender.to_string()
            }
        );
    }
}

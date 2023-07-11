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
    state::{get_current_key, KEYS, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER},
    types::{Key, Message, MultisigState, PublicKey, Signature},
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
            execute::start_signing_session(deps, info, msg.try_into()?)
        }
        ExecuteMsg::SubmitSignature { sig_id, signature } => {
            execute::submit_signature(deps, info, sig_id, signature.try_into()?)
        }
        ExecuteMsg::KeyGen { snapshot, pub_keys } => {
            execute::key_gen(deps, info, snapshot, pub_keys)
        }
    }
}

pub mod execute {
    use crate::signing::SigningSession;

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

        let key = KEYS.load(deps.storage, session.key_id.clone())?;

        session.add_signature(key, info.sender.clone().into(), signature.clone())?;

        SIGNING_SESSIONS.save(deps.storage, sig_id.u64(), &session)?;

        let event = Event::SignatureSubmitted {
            sig_id,
            participant: info.sender,
            signature,
        };

        if session.state == MultisigState::Completed {
            Ok(Response::new()
                .add_event(event.into())
                .add_event(Event::SigningCompleted { sig_id }.into()))
        } else {
            Ok(Response::new().add_event(event.into()))
        }
    }

    // TODO: this will disappear once keygen and key rotation are introduced
    pub fn key_gen(
        deps: DepsMut,
        info: MessageInfo,
        snapshot: Snapshot,
        pub_keys: HashMap<String, HexBinary>,
    ) -> Result<Response, ContractError> {
        let key = Key {
            id: info.sender.to_string(),
            snapshot,
            pub_keys: pub_keys
                .into_iter()
                .map(|(k, v)| (k, PublicKey::try_from(v).unwrap()))
                .collect(),
        };
        KEYS.save(deps.storage, key.id.clone(), &key)?;

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

        let key = KEYS.load(deps.storage, session.key_id)?;

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
        msg::GetSigningSessionResponse,
        test::common::test_data,
        test::common::{build_snapshot, TestSigner},
        types::MultisigState,
    };

    use super::*;
    use cosmwasm_std::{
        from_binary,
        testing::{mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage},
        Addr, Empty, OwnedDeps,
    };

    use serde_json::from_str;

    const INSTANTIATOR: &str = "inst";
    const BATCHER: &str = "batcher";

    fn do_instantiate(deps: DepsMut) -> Result<Response, ContractError> {
        let info = mock_info(INSTANTIATOR, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {};

        instantiate(deps, env, info, msg)
    }

    fn do_key_gen(deps: DepsMut) -> Result<Response, ContractError> {
        let info = mock_info(BATCHER, &[]);
        let env = mock_env();

        let signers = test_data::signers();
        let pub_keys = signers
            .iter()
            .map(|signer| (signer.address.clone().to_string(), signer.pub_key.clone()))
            .collect::<HashMap<String, HexBinary>>();

        let msg = ExecuteMsg::KeyGen {
            snapshot: build_snapshot(&signers),
            pub_keys,
        };

        execute(deps, env, info, msg)
    }

    fn do_start_signing_session(deps: DepsMut, sender: &str) -> Result<Response, ContractError> {
        let info = mock_info(sender, &[]);
        let env = mock_env();

        let message = test_data::message();
        let msg = ExecuteMsg::StartSigningSession {
            msg: message.clone(),
        };
        execute(deps, env, info, msg)
    }

    fn do_sign(
        deps: DepsMut,
        sig_id: Uint64,
        signer: &TestSigner,
    ) -> Result<Response, ContractError> {
        let msg = ExecuteMsg::SubmitSignature {
            sig_id,
            signature: signer.signature.clone(),
        };
        execute(
            deps,
            mock_env(),
            mock_info(signer.address.as_str(), &[]),
            msg,
        )
    }

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();
        do_key_gen(deps.as_mut()).unwrap();
        deps
    }

    fn setup_with_session_started() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = setup();
        do_start_signing_session(deps.as_mut(), BATCHER).unwrap();
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

        let session_counter = SIGNING_SESSION_COUNTER.load(deps.as_ref().storage).unwrap();

        assert_eq!(session_counter, Uint64::zero());
    }

    #[test]
    fn test_start_signing_session() {
        let mut deps = setup();

        let res = do_start_signing_session(deps.as_mut(), BATCHER);

        assert!(res.is_ok());

        let session = SIGNING_SESSIONS.load(deps.as_ref().storage, 1u64).unwrap();
        let key = get_current_key(deps.as_ref().storage, &Addr::unchecked(BATCHER)).unwrap();
        let message = test_data::message();

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
            session.id.to_string()
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

        let sender = "someone else";
        let res = do_start_signing_session(deps.as_mut(), sender);

        assert_eq!(
            res.unwrap_err(),
            ContractError::NoActiveKeyFound {
                owner: sender.to_string()
            }
        );
    }

    #[test]
    fn test_submit_signature() {
        let mut deps = setup_with_session_started();

        let signers = test_data::signers();

        let sig_id = Uint64::one();
        let signer = signers.get(0).unwrap().to_owned();
        let res = do_sign(deps.as_mut(), sig_id, &signer);

        assert!(res.is_ok());

        let session = SIGNING_SESSIONS.load(deps.as_ref().storage, 1u64).unwrap();

        assert_eq!(session.signatures.len(), 1);
        assert_eq!(
            session
                .signatures
                .get(&signer.address.clone().into_string())
                .unwrap(),
            &Signature::try_from(signer.signature.clone()).unwrap()
        );
        assert_eq!(session.state, MultisigState::Pending);

        let res = res.unwrap();
        assert_eq!(res.events.len(), 1);

        let event = res.events.get(0).unwrap();
        assert_eq!(event.ty, "signature_submitted".to_string());
        assert_eq!(
            get_event_attribute(event, "sig_id").unwrap(),
            sig_id.to_string()
        );
        assert_eq!(
            get_event_attribute(event, "participant").unwrap(),
            signer.address.into_string()
        );
        assert_eq!(
            get_event_attribute(event, "signature").unwrap(),
            signer.signature.to_hex()
        );
    }

    #[test]
    fn test_submit_signature_completed() {
        let mut deps = setup_with_session_started();

        let signers = test_data::signers();

        let sig_id = Uint64::one();
        let signer = signers.get(0).unwrap().to_owned();
        do_sign(deps.as_mut(), sig_id, &signer).unwrap();

        // second signature
        let signer = signers.get(1).unwrap().to_owned();
        let res = do_sign(deps.as_mut(), sig_id, &signer);

        assert!(res.is_ok());

        let session = SIGNING_SESSIONS.load(deps.as_ref().storage, 1u64).unwrap();

        assert_eq!(session.signatures.len(), 2);
        assert_eq!(
            session
                .signatures
                .get(&signer.address.into_string())
                .unwrap(),
            &Signature::try_from(signer.signature).unwrap()
        );
        assert_eq!(session.state, MultisigState::Completed);

        let res = res.unwrap();
        assert_eq!(res.events.len(), 2);

        let event = res.events.get(1).unwrap();
        assert_eq!(event.ty, "signing_completed".to_string());
        assert_eq!(
            get_event_attribute(event, "sig_id").unwrap(),
            sig_id.to_string()
        );
    }

    #[test]
    fn test_submit_signature_wrong_session_id() {
        let mut deps = setup_with_session_started();

        let invalid_sig_id = Uint64::zero();
        let signer = test_data::signers().get(0).unwrap().to_owned();
        let res = do_sign(deps.as_mut(), invalid_sig_id, &signer);

        assert_eq!(
            res.unwrap_err(),
            ContractError::SigningSessionNotFound {
                sig_id: invalid_sig_id
            }
        );
    }

    #[test]
    fn test_query_signing_session() {
        let mut deps = setup_with_session_started();

        let sig_id = Uint64::one();
        let signer = test_data::signers().get(0).unwrap().to_owned();
        do_sign(deps.as_mut(), sig_id, &signer).unwrap();

        let msg = QueryMsg::GetSigningSession { sig_id };

        let res = query(deps.as_ref(), mock_env(), msg);
        assert!(res.is_ok());

        let query_res: GetSigningSessionResponse = from_binary(&res.unwrap()).unwrap();
        let session = SIGNING_SESSIONS.load(deps.as_ref().storage, 1u64).unwrap();
        let key = KEYS.load(deps.as_ref().storage, session.key_id).unwrap();

        assert_eq!(query_res.state, session.state);
        assert_eq!(query_res.signatures, session.signatures);
        assert_eq!(query_res.snapshot, key.snapshot);
    }
}

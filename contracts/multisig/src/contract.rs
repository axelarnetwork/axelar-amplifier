#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult, Uint64,
};

use axelar_wasm_std::Snapshot;
use std::collections::HashMap;

use crate::{
    events::Event,
    msg::{ExecuteMsg, InstantiateMsg, Multisig, QueryMsg},
    state::{get_key, KEYS, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER},
    types::{Key, KeyID, MsgToSign, MultisigState, PublicKey, Signature},
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
        ExecuteMsg::StartSigningSession { key_id, msg } => {
            execute::start_signing_session(deps, info, key_id, msg.try_into()?)
        }
        ExecuteMsg::SubmitSignature {
            session_id,
            signature,
        } => execute::submit_signature(deps, info, session_id, signature.try_into()?),
        ExecuteMsg::KeyGen {
            key_id,
            snapshot,
            pub_keys,
        } => execute::key_gen(deps, info, key_id, snapshot, pub_keys),
    }
}

pub mod execute {
    use crate::signing::SigningSession;

    use super::*;

    pub fn start_signing_session(
        deps: DepsMut,
        info: MessageInfo,
        key_id: String,
        msg: MsgToSign,
    ) -> Result<Response, ContractError> {
        let key_id = KeyID {
            owner: info.sender,
            subkey: key_id,
        };
        let key = get_key(deps.storage, &key_id)?;

        let session_id = SIGNING_SESSION_COUNTER.update(
            deps.storage,
            |mut counter| -> Result<Uint64, ContractError> {
                counter += Uint64::one();
                Ok(counter)
            },
        )?;

        let signing_session = SigningSession::new(session_id, key.clone().id, msg.clone());

        SIGNING_SESSIONS.save(deps.storage, session_id.into(), &signing_session)?;

        let event = Event::SigningStarted {
            session_id,
            key_id: key.id,
            pub_keys: key.pub_keys,
            msg,
        };

        Ok(Response::new().add_event(event.into()))
    }

    pub fn submit_signature(
        deps: DepsMut,
        info: MessageInfo,
        session_id: Uint64,
        signature: Signature,
    ) -> Result<Response, ContractError> {
        let mut session = SIGNING_SESSIONS
            .load(deps.storage, session_id.into())
            .map_err(|_| ContractError::SigningSessionNotFound { session_id })?;

        let key = KEYS.load(deps.storage, &session.key_id)?;

        session.add_signature(key, info.sender.clone().into(), signature.clone())?;

        SIGNING_SESSIONS.save(deps.storage, session_id.u64(), &session)?;

        let event = Event::SignatureSubmitted {
            session_id,
            participant: info.sender,
            signature,
        };

        if session.state == MultisigState::Completed {
            Ok(Response::new()
                .add_event(event.into())
                .add_event(Event::SigningCompleted { session_id }.into()))
        } else {
            Ok(Response::new().add_event(event.into()))
        }
    }

    pub fn key_gen(
        deps: DepsMut,
        info: MessageInfo,
        key_id: String,
        snapshot: Snapshot,
        pub_keys: HashMap<String, HexBinary>,
    ) -> Result<Response, ContractError> {
        for participant in snapshot.participants.keys() {
            if !pub_keys.contains_key(participant) {
                return Err(ContractError::MissingPublicKey {
                    participant: participant.to_owned(),
                });
            }
        }

        let key_id = KeyID {
            owner: info.sender,
            subkey: key_id,
        };
        let key = Key {
            id: key_id.clone(),
            snapshot,
            pub_keys: pub_keys
                .into_iter()
                .map(|(k, v)| (k, PublicKey::try_from(v).unwrap()))
                .collect(),
        };

        KEYS.update(deps.storage, &key_id, |existing| match existing {
            None => Ok(key),
            _ => Err(ContractError::DuplicateKeyID {
                key_id: key_id.to_string(),
            }),
        })?;

        Ok(Response::default())
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetMultisig { session_id } => to_binary(&query::get_multisig(deps, session_id)?),
    }
}

pub mod query {
    use crate::msg::Signer;

    use super::*;

    pub fn get_multisig(deps: Deps, session_id: Uint64) -> StdResult<Multisig> {
        let session = SIGNING_SESSIONS.load(deps.storage, session_id.into())?;

        let mut key = KEYS.load(deps.storage, &session.key_id)?;

        let signers = key
            .snapshot
            .participants
            .into_iter()
            .map(|(address, participant)| {
                let pub_key = key
                    .pub_keys
                    .remove(&address)
                    .expect("violated invariant: pub_key not found");

                Signer {
                    address: participant.address,
                    weight: participant.weight.into(),
                    pub_key,
                    signature: session.signatures.get(&address).cloned(),
                }
            })
            .collect::<Vec<Signer>>();

        Ok(Multisig {
            state: session.state,
            quorum: key.snapshot.quorum.into(),
            signers,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        msg::Multisig,
        test::common::test_data,
        test::common::{build_snapshot, TestSigner},
        types::MultisigState,
    };

    use super::*;
    use cosmwasm_std::{
        from_binary,
        testing::{mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage},
        Addr, Empty, OwnedDeps, Uint256,
    };

    use serde_json::from_str;

    const INSTANTIATOR: &str = "inst";
    const PROVER: &str = "prover";

    fn do_instantiate(deps: DepsMut) -> Result<Response, ContractError> {
        let info = mock_info(INSTANTIATOR, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {};

        instantiate(deps, env, info, msg)
    }

    fn do_key_gen(deps: DepsMut) -> Result<Response, ContractError> {
        let info = mock_info(PROVER, &[]);
        let env = mock_env();

        let signers = test_data::signers();
        let pub_keys = signers
            .iter()
            .map(|signer| (signer.address.clone().to_string(), signer.pub_key.clone()))
            .collect::<HashMap<String, HexBinary>>();

        let msg = ExecuteMsg::KeyGen {
            key_id: "key".to_string(),
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
            key_id: "key".to_string(),
            msg: message.clone(),
        };
        execute(deps, env, info, msg)
    }

    fn do_sign(
        deps: DepsMut,
        session_id: Uint64,
        signer: &TestSigner,
    ) -> Result<Response, ContractError> {
        let msg = ExecuteMsg::SubmitSignature {
            session_id,
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
        do_start_signing_session(deps.as_mut(), PROVER).unwrap();
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
    fn test_key_gen() {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();

        let res = do_key_gen(deps.as_mut());
        assert!(res.is_ok());

        let res = do_key_gen(deps.as_mut());
        assert_eq!(
            res.unwrap_err(),
            ContractError::DuplicateKeyID {
                key_id: KeyID {
                    owner: Addr::unchecked(PROVER),
                    subkey: "key".to_string(),
                }
                .to_string()
            }
        );
    }

    #[test]
    fn test_start_signing_session() {
        let mut deps = setup();

        let res = do_start_signing_session(deps.as_mut(), PROVER);

        assert!(res.is_ok());

        let session = SIGNING_SESSIONS.load(deps.as_ref().storage, 1u64).unwrap();

        let key_id: KeyID = KeyID {
            owner: Addr::unchecked(PROVER),
            subkey: "key".to_string(),
        };
        let key = get_key(deps.as_ref().storage, &key_id).unwrap();
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
            get_event_attribute(event, "session_id").unwrap(),
            session.id.to_string()
        );
        assert_eq!(
            get_event_attribute(event, "key_id").unwrap(),
            session.key_id.to_string()
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
                key_id: KeyID {
                    owner: Addr::unchecked(sender),
                    subkey: "key".to_string(),
                }
                .to_string()
            }
        );
    }

    #[test]
    fn test_submit_signature() {
        let mut deps = setup_with_session_started();

        let signers = test_data::signers();

        let session_id = Uint64::one();
        let signer = signers.get(0).unwrap().to_owned();
        let res = do_sign(deps.as_mut(), session_id, &signer);

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
            get_event_attribute(event, "session_id").unwrap(),
            session_id.to_string()
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

        let session_id = Uint64::one();
        let signer = signers.get(0).unwrap().to_owned();
        do_sign(deps.as_mut(), session_id, &signer).unwrap();

        // second signature
        let signer = signers.get(1).unwrap().to_owned();
        let res = do_sign(deps.as_mut(), session_id, &signer);

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
            get_event_attribute(event, "session_id").unwrap(),
            session_id.to_string()
        );
    }

    #[test]
    fn test_submit_signature_wrong_session_id() {
        let mut deps = setup_with_session_started();

        let invalid_session_id = Uint64::zero();
        let signer = test_data::signers().get(0).unwrap().to_owned();
        let res = do_sign(deps.as_mut(), invalid_session_id, &signer);

        assert_eq!(
            res.unwrap_err(),
            ContractError::SigningSessionNotFound {
                session_id: invalid_session_id
            }
        );
    }

    #[test]
    fn test_query_signing_session() {
        let mut deps = setup_with_session_started();

        let session_id = Uint64::one();
        let signer = test_data::signers().get(0).unwrap().to_owned();
        do_sign(deps.as_mut(), session_id, &signer).unwrap();

        let msg = QueryMsg::GetMultisig { session_id };

        let res = query(deps.as_ref(), mock_env(), msg);
        assert!(res.is_ok());

        let query_res: Multisig = from_binary(&res.unwrap()).unwrap();
        let session = SIGNING_SESSIONS.load(deps.as_ref().storage, 1u64).unwrap();
        let key = KEYS
            .load(deps.as_ref().storage, (&session.key_id).into())
            .unwrap();

        assert_eq!(query_res.state, session.state);
        assert_eq!(query_res.signers.len(), key.snapshot.participants.len());
        key.snapshot
            .participants
            .iter()
            .for_each(|(address, participant)| {
                let signer = query_res
                    .signers
                    .iter()
                    .find(|signer| signer.address == participant.address)
                    .unwrap();

                assert_eq!(signer.weight, Uint256::from(participant.weight));
                assert_eq!(signer.pub_key, key.pub_keys.get(address).unwrap().clone());
                assert_eq!(signer.signature, session.signatures.get(address).cloned());
            });
    }
}

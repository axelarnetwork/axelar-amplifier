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
    msg::{ExecuteMsg, InstantiateMsg, Multisig, QueryMsg},
    state::{get_key, KEYS, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER},
    types::{Key, KeyID, MsgToSign, MultisigState},
    ContractError,
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    SIGNING_SESSION_COUNTER.save(deps.storage, &Uint64::zero())?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::StartSigningSession { key_id, msg } => execute::start_signing_session(
            deps,
            info,
            key_id,
            msg.try_into()
                .map_err(axelar_wasm_std::ContractError::from)?,
        ),
        ExecuteMsg::SubmitSignature {
            session_id,
            signature,
        } => execute::submit_signature(deps, info, session_id, signature),
        ExecuteMsg::KeyGen {
            key_id,
            snapshot,
            pub_keys_by_address,
        } => execute::key_gen(deps, info, key_id, snapshot, pub_keys_by_address),
        ExecuteMsg::RegisterPublicKey { public_key } => {
            execute::register_pub_key(deps, info, public_key)
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

pub mod execute {
    use crate::signing::sign;
    use crate::{
        key::{KeyType, KeyTyped, PublicKey, Signature},
        signing::SigningSession,
        state::PUB_KEYS,
    };

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

        Ok(Response::new()
            .set_data(to_binary(&session_id)?)
            .add_event(event.into()))
    }

    pub fn submit_signature(
        deps: DepsMut,
        info: MessageInfo,
        session_id: Uint64,
        signature: HexBinary,
    ) -> Result<Response, ContractError> {
        let session = SIGNING_SESSIONS
            .load(deps.storage, session_id.into())
            .map_err(|_| ContractError::SigningSessionNotFound { session_id })?;

        let key = KEYS.load(deps.storage, &session.key_id)?;
        let signature: Signature = match key
            .pub_keys
            .iter()
            .find(|&(addr, _)| addr == &info.sender.to_string())
        {
            None => {
                return Err(ContractError::NotAParticipant {
                    session_id,
                    signer: info.sender.into(),
                })
            }
            Some((_, pk)) => (pk.key_type(), signature).try_into()?,
        };

        let signer = info.sender.clone().into();

        let (signature, state) = sign(deps.storage, &session, &key, signer, signature)?;

        let event = Event::SignatureSubmitted {
            session_id,
            participant: info.sender,
            signature,
        };

        if state == MultisigState::Completed {
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
        pub_keys_by_address: HashMap<String, (KeyType, HexBinary)>,
    ) -> Result<Response, ContractError> {
        if snapshot.participants.len() != pub_keys_by_address.len() {
            return Err(ContractError::PublicKeysMismatchParticipants);
        }

        for participant in snapshot.participants.keys() {
            if !pub_keys_by_address.contains_key(participant) {
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
            pub_keys: pub_keys_by_address
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        PublicKey::try_from(v).expect("failed to decode public key"),
                    )
                })
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

    pub fn register_pub_key(
        deps: DepsMut,
        info: MessageInfo,
        public_key: PublicKey,
    ) -> Result<Response, ContractError> {
        PUB_KEYS.save(
            deps.storage,
            (info.sender.clone(), public_key.key_type()),
            &public_key.clone().into(),
        )?;

        Ok(Response::new().add_event(
            Event::PublicKeyRegistered {
                worker: info.sender,
                public_key,
            }
            .into(),
        ))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetMultisig { session_id } => to_binary(&query::get_multisig(deps, session_id)?),
        QueryMsg::GetKey { key_id } => to_binary(&query::get_key(deps, key_id)?),
        QueryMsg::GetPublicKey {
            worker_address,
            key_type,
        } => to_binary(&query::get_public_key(
            deps,
            deps.api.addr_validate(&worker_address)?,
            key_type,
        )?),
    }
}

pub mod query {
    use crate::{
        key::{KeyType, PublicKey},
        msg::Signer,
        signing::calculate_session_state,
        state::{session_signatures, PUB_KEYS},
    };

    use super::*;

    pub fn get_multisig(deps: Deps, session_id: Uint64) -> StdResult<Multisig> {
        let session = SIGNING_SESSIONS.load(deps.storage, session_id.into())?;

        let mut key = KEYS.load(deps.storage, &session.key_id)?;

        let signatures = session_signatures(deps.storage, session.id.u64())?;
        let state = calculate_session_state(&signatures, &key.snapshot)?;

        let signers_with_sigs = key
            .snapshot
            .participants
            .into_iter()
            .map(|(address, participant)| {
                let pub_key = key
                    .pub_keys
                    .remove(&address)
                    .expect("violated invariant: pub_key not found");

                (
                    Signer {
                        address: participant.address,
                        weight: participant.weight.into(),
                        pub_key,
                    },
                    signatures.get(&address).cloned(),
                )
            })
            .collect::<Vec<_>>();

        Ok(Multisig {
            state,
            quorum: key.snapshot.quorum.into(),
            signers: signers_with_sigs,
        })
    }

    pub fn get_key(deps: Deps, key_id: KeyID) -> StdResult<Key> {
        KEYS.load(deps.storage, &key_id)
    }

    pub fn get_public_key(deps: Deps, worker: Addr, key_type: KeyType) -> StdResult<PublicKey> {
        let raw = PUB_KEYS.load(deps.storage, (worker, key_type))?;
        Ok(PublicKey::try_from((key_type, raw)).expect("could not decode pub key"))
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::{
        key::{KeyType, PublicKey, Signature},
        msg::Multisig,
        signing::calculate_session_state,
        state::session_signatures,
        test::common::{build_snapshot, TestSigner},
        test::common::{ecdsa_test_data, ed25519_test_data},
        types::MultisigState,
    };

    use super::*;
    use cosmwasm_std::{
        from_binary,
        testing::{mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage},
        Addr, Empty, OwnedDeps, Uint256,
    };

    use serde_json::{from_str, to_string};

    const INSTANTIATOR: &str = "inst";
    const PROVER: &str = "prover";

    const ECDSA_SUBKEY: &str = "key_ecdsa";
    const ED25519_SUBKEY: &str = "key_ed25519";

    fn do_instantiate(deps: DepsMut) -> Result<Response, axelar_wasm_std::ContractError> {
        let info = mock_info(INSTANTIATOR, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {};

        instantiate(deps, env, info, msg)
    }

    fn do_key_gen(
        key_type: KeyType,
        subkey: &str,
        deps: DepsMut,
    ) -> Result<(Response, Key), axelar_wasm_std::ContractError> {
        let info = mock_info(PROVER, &[]);
        let env = mock_env();

        let signers = match key_type {
            KeyType::Ecdsa => ecdsa_test_data::signers(),
            KeyType::Ed25519 => ed25519_test_data::signers(),
        };

        let pub_keys = signers
            .iter()
            .map(|signer| {
                (
                    signer.address.clone().to_string(),
                    (key_type, signer.pub_key.clone()),
                )
            })
            .collect::<HashMap<String, (KeyType, HexBinary)>>();

        let subkey = subkey.to_string();
        let snapshot = build_snapshot(&signers);
        let msg = ExecuteMsg::KeyGen {
            key_id: subkey.clone(),
            snapshot: snapshot.clone(),
            pub_keys_by_address: pub_keys.clone(),
        };

        execute(deps, env, info.clone(), msg).map(|res| {
            (
                res,
                Key {
                    id: KeyID {
                        owner: info.sender,
                        subkey,
                    },
                    snapshot,
                    pub_keys: pub_keys
                        .iter()
                        .map(|(k, v)| (k.clone(), PublicKey::try_from(v.clone()).unwrap()))
                        .collect(),
                },
            )
        })
    }

    fn query_key(subkey: &str, deps: Deps) -> StdResult<Binary> {
        let info = mock_info(PROVER, &[]);
        let env = mock_env();
        query(
            deps,
            env,
            QueryMsg::GetKey {
                key_id: KeyID {
                    owner: info.sender,
                    subkey: subkey.to_string(),
                },
            },
        )
    }

    fn do_start_signing_session(
        deps: DepsMut,
        sender: &str,
        key_id: &str,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let info = mock_info(sender, &[]);
        let env = mock_env();

        let message = ecdsa_test_data::message();
        let msg = ExecuteMsg::StartSigningSession {
            key_id: key_id.to_string(),
            msg: message.clone(),
        };
        execute(deps, env, info, msg)
    }

    fn do_sign(
        deps: DepsMut,
        session_id: Uint64,
        signer: &TestSigner,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
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

    fn do_register_key(
        deps: DepsMut,
        worker: Addr,
        public_key: PublicKey,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let msg = ExecuteMsg::RegisterPublicKey { public_key };
        execute(deps, mock_env(), mock_info(worker.as_str(), &[]), msg)
    }

    fn query_registered_public_key(
        deps: Deps,
        worker: Addr,
        key_type: KeyType,
    ) -> StdResult<Binary> {
        let env = mock_env();
        query(
            deps,
            env,
            QueryMsg::GetPublicKey {
                worker_address: worker.to_string(),
                key_type,
            },
        )
    }

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();
        do_key_gen(KeyType::Ecdsa, ECDSA_SUBKEY, deps.as_mut()).unwrap();
        do_key_gen(KeyType::Ed25519, ED25519_SUBKEY, deps.as_mut()).unwrap();
        deps
    }

    fn setup_with_session_started(
        key_id: &str,
    ) -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = setup();
        do_start_signing_session(deps.as_mut(), PROVER, key_id).unwrap();
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

    // Returns a list of (key_type, subkey, signers, session_id)
    fn signature_test_data() -> Vec<(KeyType, &'static str, Vec<TestSigner>, Uint64)> {
        vec![
            (
                KeyType::Ecdsa,
                ECDSA_SUBKEY,
                ecdsa_test_data::signers(),
                Uint64::from(1u64),
            ),
            (
                KeyType::Ed25519,
                ED25519_SUBKEY,
                ed25519_test_data::signers(),
                Uint64::from(2u64),
            ),
        ]
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

        let res = do_key_gen(KeyType::Ecdsa, "key1", deps.as_mut());
        assert!(res.is_ok());
        let key1 = res.unwrap().1;

        let res = do_key_gen(KeyType::Ed25519, "key2", deps.as_mut());
        assert!(res.is_ok());
        let key2 = res.unwrap().1;

        let res = query_key("key1", deps.as_ref());
        assert!(res.is_ok());
        assert_eq!(key1, from_binary(&res.unwrap()).unwrap());

        let res = query_key("key2", deps.as_ref());
        assert!(res.is_ok());
        assert_eq!(key2, from_binary(&res.unwrap()).unwrap());

        for key_type in [KeyType::Ecdsa, KeyType::Ed25519] {
            let res = do_key_gen(key_type, "key1", deps.as_mut());
            assert_eq!(
                res.unwrap_err().to_string(),
                axelar_wasm_std::ContractError::from(ContractError::DuplicateKeyID {
                    key_id: KeyID {
                        owner: Addr::unchecked(PROVER),
                        subkey: "key1".to_string(),
                    }
                    .to_string()
                })
                .to_string()
            );
        }
    }

    #[test]
    fn test_start_signing_session() {
        let mut deps = setup();

        for (i, subkey) in [ECDSA_SUBKEY, ED25519_SUBKEY].into_iter().enumerate() {
            let res = do_start_signing_session(deps.as_mut(), PROVER, subkey);

            assert!(res.is_ok());

            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, i as u64 + 1)
                .unwrap();

            let key_id: KeyID = KeyID {
                owner: Addr::unchecked(PROVER),
                subkey: subkey.to_string(),
            };
            let key = get_key(deps.as_ref().storage, &key_id).unwrap();
            let message = match subkey {
                ECDSA_SUBKEY => ecdsa_test_data::message(),
                ED25519_SUBKEY => ed25519_test_data::message(),
                _ => panic!("unexpected subkey"),
            };
            let signatures = session_signatures(deps.as_ref().storage, session.id.u64()).unwrap();

            assert_eq!(session.id, Uint64::from(i as u64 + 1));
            assert_eq!(session.key_id, key.id);
            assert_eq!(session.msg, message.clone().try_into().unwrap());
            assert!(signatures.is_empty());
            assert_eq!(
                calculate_session_state(&signatures, &key.snapshot).unwrap(),
                MultisigState::Pending
            );

            let res = res.unwrap();
            assert_eq!(res.data, Some(to_binary(&session.id).unwrap()));
            assert_eq!(res.events.len(), 1);

            let event = res.events.get(0).unwrap();
            assert_eq!(event.ty, "signing_started".to_string());
            assert_eq!(
                get_event_attribute(event, "session_id").unwrap(),
                session.id.to_string()
            );
            assert_eq!(
                get_event_attribute(event, "key_id").unwrap(),
                to_string(&session.key_id).unwrap()
            );
            assert_eq!(
                key.pub_keys,
                from_str(get_event_attribute(event, "pub_keys").unwrap()).unwrap()
            );
            assert_eq!(get_event_attribute(event, "msg").unwrap(), message.to_hex());
        }
    }

    #[test]
    fn test_start_signing_session_wrong_sender() {
        let mut deps = setup();

        let sender = "someone else";

        for key_id in [ECDSA_SUBKEY, ED25519_SUBKEY] {
            let res = do_start_signing_session(deps.as_mut(), sender, key_id);

            assert_eq!(
                res.unwrap_err().to_string(),
                axelar_wasm_std::ContractError::from(ContractError::NoActiveKeyFound {
                    key_id: KeyID {
                        owner: Addr::unchecked(sender),
                        subkey: key_id.to_string(),
                    }
                    .to_string()
                })
                .to_string()
            );
        }
    }

    #[test]
    fn test_submit_signature() {
        let mut deps = setup();

        for (key_type, subkey, signers, session_id) in signature_test_data() {
            do_start_signing_session(deps.as_mut(), PROVER, subkey).unwrap();

            let signer = signers.get(0).unwrap().to_owned();
            let res = do_sign(deps.as_mut(), Uint64::from(session_id), &signer);

            assert!(res.is_ok());

            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, session_id.into())
                .unwrap();
            let key = get_key(deps.as_ref().storage, &session.key_id).unwrap();
            let signatures = session_signatures(deps.as_ref().storage, session.id.u64()).unwrap();

            assert_eq!(signatures.len(), 1);
            assert_eq!(
                signatures
                    .get(&signer.address.clone().into_string())
                    .unwrap(),
                &Signature::try_from((key_type, signer.signature.clone())).unwrap()
            );
            assert_eq!(
                calculate_session_state(&signatures, &key.snapshot).unwrap(),
                MultisigState::Pending
            );

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
    }

    #[test]
    fn test_submit_signature_completed() {
        let mut deps = setup();

        for (key_type, subkey, signers, session_id) in signature_test_data() {
            do_start_signing_session(deps.as_mut(), PROVER, subkey).unwrap();

            let signer = signers.get(0).unwrap().to_owned();
            do_sign(deps.as_mut(), session_id, &signer).unwrap();

            // second signature
            let signer = signers.get(1).unwrap().to_owned();
            let res = do_sign(deps.as_mut(), session_id, &signer);

            assert!(res.is_ok());

            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, session_id.into())
                .unwrap();
            let key = get_key(deps.as_ref().storage, &session.key_id).unwrap();
            let signatures = session_signatures(deps.as_ref().storage, session.id.u64()).unwrap();

            assert_eq!(signatures.len(), 2);
            assert_eq!(
                signatures.get(&signer.address.into_string()).unwrap(),
                &Signature::try_from((key_type, signer.signature)).unwrap()
            );
            assert_eq!(
                calculate_session_state(&signatures, &key.snapshot).unwrap(),
                MultisigState::Completed
            );

            let res = res.unwrap();
            assert_eq!(res.events.len(), 2);

            let event = res.events.get(1).unwrap();
            assert_eq!(event.ty, "signing_completed".to_string());
            assert_eq!(
                get_event_attribute(event, "session_id").unwrap(),
                session_id.to_string()
            );
        }
    }

    #[test]
    fn test_submit_signature_wrong_session_id() {
        let mut deps = setup_with_session_started(ECDSA_SUBKEY);

        let invalid_session_id = Uint64::zero();
        let signer = ecdsa_test_data::signers().get(0).unwrap().to_owned();
        let res = do_sign(deps.as_mut(), invalid_session_id, &signer);

        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::SigningSessionNotFound {
                session_id: invalid_session_id
            })
            .to_string()
        );
    }

    #[test]
    fn test_query_signing_session() {
        let mut deps = setup();

        for (_key_type, subkey, signers, session_id) in signature_test_data() {
            do_start_signing_session(deps.as_mut(), PROVER, subkey).unwrap();

            do_sign(deps.as_mut(), session_id, signers.get(0).unwrap()).unwrap();
            do_sign(deps.as_mut(), session_id, signers.get(1).unwrap()).unwrap();

            let msg = QueryMsg::GetMultisig { session_id };

            let res = query(deps.as_ref(), mock_env(), msg);
            assert!(res.is_ok());

            let query_res: Multisig = from_binary(&res.unwrap()).unwrap();
            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, session_id.into())
                .unwrap();
            let key = KEYS
                .load(deps.as_ref().storage, (&session.key_id).into())
                .unwrap();
            let signatures = session_signatures(deps.as_ref().storage, session.id.u64()).unwrap();

            assert_eq!(query_res.state, MultisigState::Completed);
            assert_eq!(query_res.signers.len(), key.snapshot.participants.len());
            key.snapshot
                .participants
                .iter()
                .for_each(|(address, participant)| {
                    let signer = query_res
                        .signers
                        .iter()
                        .find(|signer| signer.0.address == participant.address)
                        .unwrap();

                    assert_eq!(signer.0.weight, Uint256::from(participant.weight));
                    assert_eq!(signer.0.pub_key, key.pub_keys.get(address).unwrap().clone());
                    assert_eq!(signer.1, signatures.get(address).cloned());
                });
        }
    }

    #[test]
    fn test_register_key() {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();

        // Register an ECDSA key
        let ecdsa_signers = ecdsa_test_data::signers();
        let ecdsa_pub_keys = ecdsa_signers
            .iter()
            .map(|signer| (signer.address.clone(), signer.pub_key.clone()))
            .collect::<Vec<(Addr, HexBinary)>>();

        for (addr, pub_key) in &ecdsa_pub_keys {
            let res = do_register_key(
                deps.as_mut(),
                addr.clone(),
                PublicKey::Ecdsa(pub_key.clone()),
            );
            assert!(res.is_ok());
        }

        // Register an ED25519 key
        let ed25519_signers = ed25519_test_data::signers();
        let ed25519_pub_keys = ed25519_signers
            .iter()
            .map(|signer| (signer.address.clone(), signer.pub_key.clone()))
            .collect::<Vec<(Addr, HexBinary)>>();

        for (addr, pub_key) in &ed25519_pub_keys {
            let res = do_register_key(
                deps.as_mut(),
                addr.clone(),
                PublicKey::Ed25519(pub_key.clone()),
            );
            assert!(res.is_ok());
        }

        // Test that we can query both keys
        for (key_type, expected_pub_keys) in [
            (KeyType::Ecdsa, ecdsa_pub_keys),
            (KeyType::Ed25519, ed25519_pub_keys),
        ] {
            let mut ret_pub_keys: Vec<PublicKey> = vec![];

            for (addr, _) in &expected_pub_keys {
                let res = query_registered_public_key(deps.as_ref(), addr.clone(), key_type);
                assert!(res.is_ok());
                ret_pub_keys.push(from_binary(&res.unwrap()).unwrap());
            }
            assert_eq!(
                expected_pub_keys
                    .into_iter()
                    .map(|(_, pk)| PublicKey::try_from((key_type, pk)).unwrap())
                    .collect::<Vec<PublicKey>>(),
                ret_pub_keys
            );
        }
    }

    #[test]
    fn test_update_key() {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();
        let signers = ecdsa_test_data::signers();
        let pub_keys = signers
            .iter()
            .map(|signer| (signer.address.clone(), signer.pub_key.clone()))
            .collect::<Vec<(Addr, HexBinary)>>();

        for (addr, pub_key) in &pub_keys {
            let res = do_register_key(
                deps.as_mut(),
                addr.clone(),
                PublicKey::Ecdsa(pub_key.clone()),
            );
            assert!(res.is_ok());
        }

        // Update ECDSA key
        let new_pub_key = HexBinary::from_hex(
            "021a381b3e07347d3a05495347e1fb2fe04764afcea5a74084fa957947b59f9026",
        )
        .unwrap();
        let res = do_register_key(
            deps.as_mut(),
            pub_keys[0].0.clone(),
            PublicKey::Ecdsa(new_pub_key.clone()),
        );
        assert!(res.is_ok());

        let res = query_registered_public_key(deps.as_ref(), pub_keys[0].0.clone(), KeyType::Ecdsa);
        assert!(res.is_ok());
        assert_eq!(
            PublicKey::try_from((KeyType::Ecdsa, new_pub_key.clone())).unwrap(),
            from_binary::<PublicKey>(&res.unwrap()).unwrap()
        );

        // Register an ED25519 key, it should not affect our ECDSA key
        let ed25519_pub_key =
            HexBinary::from_hex("13606a37daa030d02a72986dc01e45904678c8001429cd34514e69e2d054636a")
                .unwrap();

        let res = do_register_key(
            deps.as_mut(),
            pub_keys[0].0.clone(),
            PublicKey::Ed25519(ed25519_pub_key.clone()),
        );
        assert!(res.is_ok());

        let res =
            query_registered_public_key(deps.as_ref(), pub_keys[0].0.clone(), KeyType::Ed25519);
        assert!(res.is_ok());
        assert_eq!(
            PublicKey::try_from((KeyType::Ed25519, ed25519_pub_key)).unwrap(),
            from_binary::<PublicKey>(&res.unwrap()).unwrap()
        );

        let res = query_registered_public_key(deps.as_ref(), pub_keys[0].0.clone(), KeyType::Ecdsa);
        assert!(res.is_ok());
        assert_eq!(
            PublicKey::try_from((KeyType::Ecdsa, new_pub_key)).unwrap(),
            from_binary::<PublicKey>(&res.unwrap()).unwrap()
        );
    }
}

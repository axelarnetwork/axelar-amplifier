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
        let mut session = SIGNING_SESSIONS
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
        state::PUB_KEYS,
    };

    use super::*;

    pub fn get_multisig(deps: Deps, session_id: Uint64) -> StdResult<Multisig> {
        let session = SIGNING_SESSIONS.load(deps.storage, session_id.into())?;

        let mut key = KEYS.load(deps.storage, &session.key_id)?;

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
                    session.signatures.get(&address).cloned(),
                )
            })
            .collect::<Vec<_>>();

        Ok(Multisig {
            state: session.state,
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

    use serde_json::{from_str, to_string};

    const INSTANTIATOR: &str = "inst";
    const PROVER: &str = "prover";

    fn do_instantiate(deps: DepsMut) -> Result<Response, axelar_wasm_std::ContractError> {
        let info = mock_info(INSTANTIATOR, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {};

        instantiate(deps, env, info, msg)
    }

    fn do_key_gen(deps: DepsMut) -> Result<(Response, Key), axelar_wasm_std::ContractError> {
        let info = mock_info(PROVER, &[]);
        let env = mock_env();

        let signers = test_data::signers();
        let pub_keys = signers
            .iter()
            .map(|signer| {
                (
                    signer.address.clone().to_string(),
                    (KeyType::Ecdsa, signer.pub_key.clone()),
                )
            })
            .collect::<HashMap<String, (KeyType, HexBinary)>>();
        let subkey = "key".to_string();

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

    fn query_key(deps: Deps) -> StdResult<Binary> {
        let info = mock_info(PROVER, &[]);
        let env = mock_env();
        query(
            deps,
            env,
            QueryMsg::GetKey {
                key_id: KeyID {
                    owner: info.sender,
                    subkey: "key".to_string(),
                },
            },
        )
    }

    fn do_start_signing_session(
        deps: DepsMut,
        sender: &str,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
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
        let key = res.unwrap().1;

        let res = query_key(deps.as_ref());
        assert!(res.is_ok());
        assert_eq!(key, from_binary(&res.unwrap()).unwrap());

        let res = do_key_gen(deps.as_mut());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::DuplicateKeyID {
                key_id: KeyID {
                    owner: Addr::unchecked(PROVER),
                    subkey: "key".to_string(),
                }
                .to_string()
            })
            .to_string()
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

    #[test]
    fn test_start_signing_session_wrong_sender() {
        let mut deps = setup();

        let sender = "someone else";
        let res = do_start_signing_session(deps.as_mut(), sender);

        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::NoActiveKeyFound {
                key_id: KeyID {
                    owner: Addr::unchecked(sender),
                    subkey: "key".to_string(),
                }
                .to_string()
            })
            .to_string()
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
            &Signature::try_from((KeyType::Ecdsa, signer.signature.clone())).unwrap()
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
            &Signature::try_from((KeyType::Ecdsa, signer.signature)).unwrap()
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
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::SigningSessionNotFound {
                session_id: invalid_session_id
            })
            .to_string()
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
                    .find(|signer| signer.0.address == participant.address)
                    .unwrap();

                assert_eq!(signer.0.weight, Uint256::from(participant.weight));
                assert_eq!(signer.0.pub_key, key.pub_keys.get(address).unwrap().clone());
                assert_eq!(signer.1, session.signatures.get(address).cloned());
            });
    }
    #[test]
    fn test_register_key() {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();
        let signers = test_data::signers();
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
        let mut ret_pub_keys: Vec<PublicKey> = vec![];

        for (addr, _) in &pub_keys {
            let res = query_registered_public_key(deps.as_ref(), addr.clone(), KeyType::Ecdsa);
            assert!(res.is_ok());
            ret_pub_keys.push(from_binary(&res.unwrap()).unwrap());
        }
        assert_eq!(
            pub_keys
                .into_iter()
                .map(|(_, pk)| PublicKey::try_from((KeyType::Ecdsa, pk)).unwrap())
                .collect::<Vec<PublicKey>>(),
            ret_pub_keys
        );
    }

    #[test]
    fn test_update_key() {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();
        let signers = test_data::signers();
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
            PublicKey::try_from((KeyType::Ecdsa, new_pub_key)).unwrap(),
            from_binary::<PublicKey>(&res.unwrap()).unwrap()
        );
    }
}

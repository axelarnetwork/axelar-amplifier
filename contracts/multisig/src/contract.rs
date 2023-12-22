#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult,
    Uint64,
};

use crate::{
    events::Event,
    msg::{ExecuteMsg, InstantiateMsg, Multisig, QueryMsg},
    state::{
        get_worker_set, Config, CONFIG, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER, WORKER_SETS,
    },
    types::{MsgToSign, MultisigState},
    ContractError,
};

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let config = Config {
        governance: deps.api.addr_validate(&msg.governance_address)?,
        rewards_contract: deps.api.addr_validate(&msg.rewards_address)?,
        grace_period: msg.grace_period,
    };
    CONFIG.save(deps.storage, &config)?;

    SIGNING_SESSION_COUNTER.save(deps.storage, &Uint64::zero())?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::StartSigningSession {
            worker_set_id,
            msg,
            chain_name,
            sig_verifier,
        } => {
            execute::require_authorized_caller(&deps, info.sender)?;

            let _sig_verifier = sig_verifier
                .map(|addr| deps.api.addr_validate(&addr))
                .transpose()?; // TODO: handle callback
            execute::start_signing_session(
                deps,
                worker_set_id,
                msg.try_into()
                    .map_err(axelar_wasm_std::ContractError::from)?,
                chain_name,
            )
        }
        ExecuteMsg::SubmitSignature {
            session_id,
            signature,
        } => execute::submit_signature(deps, env, info, session_id, signature),
        ExecuteMsg::RegisterWorkerSet { worker_set } => {
            execute::register_worker_set(deps, worker_set)
        }
        ExecuteMsg::RegisterPublicKey { public_key } => {
            execute::register_pub_key(deps, info, public_key)
        }
        ExecuteMsg::AuthorizeCaller { contract_address } => {
            execute::require_governance(&deps, info.sender)?;
            execute::authorize_caller(deps, contract_address)
        }
        ExecuteMsg::UnauthorizeCaller { contract_address } => {
            execute::require_governance(&deps, info.sender)?;
            execute::unauthorize_caller(deps, contract_address)
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

pub mod execute {
    use connection_router::state::ChainName;
    use cosmwasm_std::WasmMsg;

    use crate::signing::validate_session_signature;
    use crate::state::{load_session_signatures, save_signature};
    use crate::worker_set::WorkerSet;
    use crate::{
        key::{KeyTyped, PublicKey, Signature},
        signing::SigningSession,
        state::{AUTHORIZED_CALLERS, PUB_KEYS},
    };
    use error_stack::ResultExt;

    use super::*;

    pub fn start_signing_session(
        deps: DepsMut,
        worker_set_id: String,
        msg: MsgToSign,
        chain_name: ChainName,
    ) -> Result<Response, ContractError> {
        let worker_set = get_worker_set(deps.storage, &worker_set_id)?;

        let session_id = SIGNING_SESSION_COUNTER.update(
            deps.storage,
            |mut counter| -> Result<Uint64, ContractError> {
                counter += Uint64::one();
                Ok(counter)
            },
        )?;

        let signing_session = SigningSession::new(session_id, worker_set_id.clone(), msg.clone());

        SIGNING_SESSIONS.save(deps.storage, session_id.into(), &signing_session)?;

        let event = Event::SigningStarted {
            session_id,
            worker_set_id,
            pub_keys: worker_set.get_pub_keys(),
            msg,
            chain_name,
        };

        Ok(Response::new()
            .set_data(to_binary(&session_id)?)
            .add_event(event.into()))
    }

    pub fn submit_signature(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        session_id: Uint64,
        signature: HexBinary,
    ) -> Result<Response, ContractError> {
        let config = CONFIG.load(deps.storage)?;
        let mut session = SIGNING_SESSIONS
            .load(deps.storage, session_id.into())
            .map_err(|_| ContractError::SigningSessionNotFound { session_id })?;
        let worker_set = WORKER_SETS.load(deps.storage, &session.worker_set_id)?;

        let pub_key = match worker_set.signers.get(&info.sender.to_string()) {
            Some(signer) => Ok(&signer.pub_key),
            None => Err(ContractError::NotAParticipant {
                session_id,
                signer: info.sender.to_string(),
            }),
        }?;

        let signature: Signature = (pub_key.key_type(), signature).try_into()?;

        validate_session_signature(
            &session,
            &info.sender,
            &signature,
            pub_key,
            config.grace_period,
            env.block.height,
        )?;
        let signature = save_signature(deps.storage, session_id, signature, &info.sender)?;

        let signatures = load_session_signatures(deps.storage, session_id.u64())?;

        let old_state = session.state.clone();

        session.recalculate_session_state(&signatures, &worker_set, env.block.height);
        SIGNING_SESSIONS.save(deps.storage, session.id.u64(), &session)?;

        let state_changed = old_state != session.state;

        signing_response(
            session_id,
            session.state,
            state_changed,
            info.sender,
            signature,
            config.rewards_contract.into_string(),
        )
    }

    pub fn register_worker_set(
        deps: DepsMut,
        worker_set: WorkerSet,
    ) -> Result<Response, ContractError> {
        let worker_set_id = worker_set.id();
        WORKER_SETS.save(deps.storage, &worker_set_id, &worker_set)?;

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

    pub fn require_authorized_caller(
        deps: &DepsMut,
        contract_address: Addr,
    ) -> error_stack::Result<(), ContractError> {
        AUTHORIZED_CALLERS
            .load(deps.storage, &contract_address)
            .change_context(ContractError::Unauthorized)
    }

    pub fn authorize_caller(
        deps: DepsMut,
        contract_address: Addr,
    ) -> Result<Response, ContractError> {
        AUTHORIZED_CALLERS.save(deps.storage, &contract_address, &())?;

        Ok(Response::new().add_event(Event::CallerAuthorized { contract_address }.into()))
    }

    pub fn unauthorize_caller(
        deps: DepsMut,
        contract_address: Addr,
    ) -> Result<Response, ContractError> {
        AUTHORIZED_CALLERS.remove(deps.storage, &contract_address);

        Ok(Response::new().add_event(Event::CallerUnauthorized { contract_address }.into()))
    }

    pub fn require_governance(deps: &DepsMut, sender: Addr) -> Result<(), ContractError> {
        let config = CONFIG.load(deps.storage)?;
        if config.governance != sender {
            return Err(ContractError::Unauthorized);
        }
        Ok(())
    }

    fn signing_response(
        session_id: Uint64,
        session_state: MultisigState,
        state_changed: bool,
        signer: Addr,
        signature: Signature,
        rewards_contract: String,
    ) -> Result<Response, ContractError> {
        let rewards_msg = WasmMsg::Execute {
            contract_addr: rewards_contract,
            msg: to_binary(&rewards::msg::ExecuteMsg::RecordParticipation {
                event_id: session_id
                    .to_string()
                    .try_into()
                    .expect("couldn't convert session_id to nonempty string"),
                worker_address: signer.to_string(),
            })?,
            funds: vec![],
        };

        let event = Event::SignatureSubmitted {
            session_id,
            participant: signer,
            signature,
        };

        let mut response = Response::new()
            .add_message(rewards_msg)
            .add_event(event.into());

        if let MultisigState::Completed { completed_at } = session_state {
            if state_changed {
                // only send event if state changed
                response = response.add_event(
                    Event::SigningCompleted {
                        session_id,
                        completed_at,
                    }
                    .into(),
                )
            }
        }

        Ok(response)
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetMultisig { session_id } => to_binary(&query::get_multisig(deps, session_id)?),
        QueryMsg::GetWorkerSet { worker_set_id } => {
            to_binary(&query::get_worker_set(deps, worker_set_id)?)
        }
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
        state::{load_session_signatures, PUB_KEYS},
        worker_set::WorkerSet,
    };

    use super::*;

    pub fn get_multisig(deps: Deps, session_id: Uint64) -> StdResult<Multisig> {
        let session = SIGNING_SESSIONS.load(deps.storage, session_id.into())?;

        let worker_set = WORKER_SETS.load(deps.storage, &session.worker_set_id)?;
        let signatures = load_session_signatures(deps.storage, session.id.u64())?;

        let signers_with_sigs = worker_set
            .signers
            .into_iter()
            .map(|(address, signer)| (signer, signatures.get(&address).cloned()))
            .collect::<Vec<_>>();

        Ok(Multisig {
            state: session.state,
            quorum: worker_set.threshold,
            signers: signers_with_sigs,
        })
    }

    pub fn get_worker_set(deps: Deps, worker_set_id: String) -> StdResult<WorkerSet> {
        WORKER_SETS.load(deps.storage, &worker_set_id)
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
        state::load_session_signatures,
        test::common::{build_worker_set, TestSigner},
        test::common::{ecdsa_test_data, ed25519_test_data},
        types::MultisigState,
        worker_set::WorkerSet,
    };

    use super::*;
    use cosmwasm_std::{
        from_binary,
        testing::{mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage},
        Addr, Empty, OwnedDeps, Uint256, WasmMsg,
    };

    use serde_json::from_str;

    const INSTANTIATOR: &str = "inst";
    const PROVER: &str = "prover";
    const REWARDS_CONTRACT: &str = "rewards";

    fn do_instantiate(deps: DepsMut) -> Result<Response, axelar_wasm_std::ContractError> {
        let info = mock_info(INSTANTIATOR, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {
            governance_address: "governance".parse().unwrap(),
            rewards_address: REWARDS_CONTRACT.to_string(),
            grace_period: 2,
        };

        instantiate(deps, env, info, msg)
    }

    fn generate_worker_set(
        key_type: KeyType,
        deps: DepsMut,
    ) -> Result<(Response, WorkerSet), axelar_wasm_std::ContractError> {
        let info = mock_info(PROVER, &[]);
        let env = mock_env();

        let signers = match key_type {
            KeyType::Ecdsa => ecdsa_test_data::signers(),
            KeyType::Ed25519 => ed25519_test_data::signers(),
        };

        let worker_set = build_worker_set(key_type, &signers);
        let msg = ExecuteMsg::RegisterWorkerSet {
            worker_set: worker_set.clone(),
        };

        execute(deps, env, info.clone(), msg).map(|res| (res, worker_set))
    }

    fn query_worker_set(worker_set_id: &str, deps: Deps) -> StdResult<Binary> {
        let env = mock_env();
        query(
            deps,
            env,
            QueryMsg::GetWorkerSet {
                worker_set_id: worker_set_id.to_string(),
            },
        )
    }

    fn do_start_signing_session(
        deps: DepsMut,
        sender: &str,
        worker_set_id: &str,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let info = mock_info(sender, &[]);
        let env = mock_env();

        let message = ecdsa_test_data::message();
        let msg = ExecuteMsg::StartSigningSession {
            worker_set_id: worker_set_id.to_string(),
            msg: message.clone(),
            chain_name: "Ethereum".to_string().try_into().unwrap(),
            sig_verifier: None,
        };
        execute(deps, env, info, msg)
    }

    fn do_sign(
        deps: DepsMut,
        env: Env,
        session_id: Uint64,
        signer: &TestSigner,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let msg = ExecuteMsg::SubmitSignature {
            session_id,
            signature: signer.signature.clone(),
        };
        execute(deps, env, mock_info(signer.address.as_str(), &[]), msg)
    }

    fn do_register_key(
        deps: DepsMut,
        worker: Addr,
        public_key: PublicKey,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let msg = ExecuteMsg::RegisterPublicKey { public_key };
        execute(deps, mock_env(), mock_info(worker.as_str(), &[]), msg)
    }

    fn do_authorize_caller(
        deps: DepsMut,
        contract_address: Addr,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let config = CONFIG.load(deps.storage)?;
        let info = mock_info(config.governance.as_str(), &[]);
        let env = mock_env();

        let msg = ExecuteMsg::AuthorizeCaller { contract_address };
        execute(deps, env, info, msg)
    }

    fn do_unauthorize_caller(
        deps: DepsMut,
        contract_address: Addr,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let config = CONFIG.load(deps.storage)?;
        let info = mock_info(config.governance.as_str(), &[]);
        let env = mock_env();

        let msg = ExecuteMsg::UnauthorizeCaller { contract_address };
        execute(deps, env, info, msg)
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

    fn setup() -> (
        OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
        String,
        String,
    ) {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();
        let worker_set_ecdsa = generate_worker_set(KeyType::Ecdsa, deps.as_mut())
            .unwrap()
            .1;
        let worker_set_ed25519 = generate_worker_set(KeyType::Ed25519, deps.as_mut())
            .unwrap()
            .1;
        let ecdsa_subkey = worker_set_ecdsa.id();
        let ed25519_subkey = worker_set_ed25519.id();

        (deps, ecdsa_subkey, ed25519_subkey)
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
    fn signature_test_data<'a>(
        ecdsa_subkey: &'a String,
        ed25519_subkey: &'a String,
    ) -> Vec<(KeyType, &'a String, Vec<TestSigner>, Uint64)> {
        vec![
            (
                KeyType::Ecdsa,
                ecdsa_subkey,
                ecdsa_test_data::signers(),
                Uint64::from(1u64),
            ),
            (
                KeyType::Ed25519,
                ed25519_subkey,
                ed25519_test_data::signers(),
                Uint64::from(2u64),
            ),
        ]
    }

    #[test]
    fn instantiation() {
        let mut deps = mock_dependencies();

        let res = do_instantiate(deps.as_mut());
        assert!(res.is_ok());
        assert_eq!(0, res.unwrap().messages.len());

        let session_counter = SIGNING_SESSION_COUNTER.load(deps.as_ref().storage).unwrap();

        assert_eq!(session_counter, Uint64::zero());
    }

    #[test]
    fn update_worker_set() {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();

        let res = generate_worker_set(KeyType::Ecdsa, deps.as_mut());
        assert!(res.is_ok());
        let worker_set_1 = res.unwrap().1;
        let worker_set_1_id = worker_set_1.id();

        let res = generate_worker_set(KeyType::Ed25519, deps.as_mut());
        assert!(res.is_ok());
        let worker_set_2 = res.unwrap().1;
        let worker_set_2_id = worker_set_2.id();

        let res = query_worker_set(&worker_set_1.id(), deps.as_ref());
        assert!(res.is_ok());
        assert_eq!(worker_set_1, from_binary(&res.unwrap()).unwrap());

        let res = query_worker_set(&worker_set_2.id(), deps.as_ref());
        assert!(res.is_ok());
        assert_eq!(worker_set_2, from_binary(&res.unwrap()).unwrap());

        for (key_type, _) in [
            (KeyType::Ecdsa, worker_set_1_id),
            (KeyType::Ed25519, worker_set_2_id),
        ] {
            let res = generate_worker_set(key_type, deps.as_mut());
            assert!(res.is_ok());
        }
    }

    #[test]
    fn start_signing_session() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        do_authorize_caller(deps.as_mut(), Addr::unchecked(PROVER)).unwrap();

        for (i, subkey) in [ecdsa_subkey.clone(), ed25519_subkey.clone()]
            .into_iter()
            .enumerate()
        {
            let res = do_start_signing_session(deps.as_mut(), PROVER, &subkey);

            assert!(res.is_ok());

            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, i as u64 + 1)
                .unwrap();

            let worker_set_id = subkey.to_string();
            let worker_set = get_worker_set(deps.as_ref().storage, &worker_set_id).unwrap();
            let message = match subkey {
                _ if subkey == ecdsa_subkey => ecdsa_test_data::message(),
                _ if subkey == ed25519_subkey => ed25519_test_data::message(),
                _ => panic!("unexpected subkey"),
            };
            let signatures =
                load_session_signatures(deps.as_ref().storage, session.id.u64()).unwrap();

            assert_eq!(session.id, Uint64::from(i as u64 + 1));
            assert_eq!(session.worker_set_id, worker_set_id);
            assert_eq!(session.msg, message.clone().try_into().unwrap());
            assert!(signatures.is_empty());
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
                get_event_attribute(event, "worker_set_id").unwrap(),
                session.worker_set_id
            );
            assert_eq!(
                worker_set.get_pub_keys(),
                from_str(get_event_attribute(event, "pub_keys").unwrap()).unwrap()
            );
            assert_eq!(get_event_attribute(event, "msg").unwrap(), message.to_hex());
        }
    }

    #[test]
    fn start_signing_session_wrong_sender() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        do_authorize_caller(deps.as_mut(), Addr::unchecked(PROVER)).unwrap();

        let sender = "someone else";

        for worker_set_id in [ecdsa_subkey, ed25519_subkey] {
            let res = do_start_signing_session(deps.as_mut(), sender, &worker_set_id);

            assert_eq!(
                res.unwrap_err().to_string(),
                axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
                    + ": () not found"
            );
        }
    }

    #[test]
    fn submit_signature() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        do_authorize_caller(deps.as_mut(), Addr::unchecked(PROVER)).unwrap();

        for (key_type, worker_set_id, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(deps.as_mut(), PROVER, worker_set_id).unwrap();

            let signer = signers.get(0).unwrap().to_owned();

            let expected_rewards_msg = WasmMsg::Execute {
                contract_addr: REWARDS_CONTRACT.to_string(),
                msg: to_binary(&rewards::msg::ExecuteMsg::RecordParticipation {
                    event_id: session_id.to_string().try_into().unwrap(),
                    worker_address: signer.address.clone().into(),
                })
                .unwrap(),
                funds: vec![],
            }
            .into();

            let res = do_sign(deps.as_mut(), mock_env(), Uint64::from(session_id), &signer);

            assert!(res.is_ok());

            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, session_id.into())
                .unwrap();
            let signatures =
                load_session_signatures(deps.as_ref().storage, session.id.u64()).unwrap();

            assert_eq!(signatures.len(), 1);
            assert_eq!(
                signatures
                    .get(&signer.address.clone().into_string())
                    .unwrap(),
                &Signature::try_from((key_type, signer.signature.clone())).unwrap()
            );
            assert_eq!(session.state, MultisigState::Pending);

            let res = res.unwrap();
            assert_eq!(res.events.len(), 1);

            assert!(res.messages.iter().any(|m| m.msg == expected_rewards_msg));

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
    fn submit_signature_completes_session() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        do_authorize_caller(deps.as_mut(), Addr::unchecked(PROVER)).unwrap();

        for (key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(deps.as_mut(), PROVER, subkey).unwrap();

            let signer = signers.get(0).unwrap().to_owned();
            do_sign(deps.as_mut(), mock_env(), session_id, &signer).unwrap();

            // second signature
            let env = mock_env();
            let expected_completed_at = env.block.height;

            let signer = signers.get(1).unwrap().to_owned();
            let res = do_sign(deps.as_mut(), env, session_id, &signer);

            assert!(res.is_ok());

            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, session_id.into())
                .unwrap();
            let signatures =
                load_session_signatures(deps.as_ref().storage, session.id.u64()).unwrap();

            assert_eq!(signatures.len(), 2);
            assert_eq!(
                signatures.get(&signer.address.into_string()).unwrap(),
                &Signature::try_from((key_type, signer.signature)).unwrap()
            );
            assert_eq!(
                session.state,
                MultisigState::Completed {
                    completed_at: expected_completed_at
                }
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
    fn submit_signature_during_grace_period() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        do_authorize_caller(deps.as_mut(), Addr::unchecked(PROVER)).unwrap();

        for (_key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(deps.as_mut(), PROVER, subkey).unwrap();

            let signer = signers.get(0).unwrap().to_owned();
            do_sign(deps.as_mut(), mock_env(), session_id, &signer).unwrap();

            // second signature
            let signer = signers.get(1).unwrap().to_owned();
            do_sign(deps.as_mut(), mock_env(), session_id, &signer).unwrap();

            // third signature, grace period
            let signer = signers.get(2).unwrap().to_owned();

            let expected_rewards_msg = WasmMsg::Execute {
                contract_addr: REWARDS_CONTRACT.to_string(),
                msg: to_binary(&rewards::msg::ExecuteMsg::RecordParticipation {
                    event_id: session_id.to_string().try_into().unwrap(),
                    worker_address: signer.address.clone().into(),
                })
                .unwrap(),
                funds: vec![],
            }
            .into();

            let mut env = mock_env();
            env.block.height += 1;
            let res = do_sign(deps.as_mut(), env, session_id, &signer).unwrap();
            let signatures =
                load_session_signatures(deps.as_ref().storage, session_id.u64()).unwrap();

            assert_eq!(signatures.len(), 3);
            assert!(res.messages.iter().any(|m| m.msg == expected_rewards_msg));
            assert!(!res
                .events
                .iter()
                .any(|e| e.ty == "signing_completed".to_string())); // event is not re-emitted during grace period
        }
    }

    #[test]
    fn submit_signature_grace_period_over() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        do_authorize_caller(deps.as_mut(), Addr::unchecked(PROVER)).unwrap();

        for (_key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(deps.as_mut(), PROVER, subkey).unwrap();

            let signer = signers.get(0).unwrap().to_owned();
            do_sign(deps.as_mut(), mock_env(), session_id, &signer).unwrap();

            // second signature
            let signer = signers.get(1).unwrap().to_owned();
            do_sign(deps.as_mut(), mock_env(), session_id, &signer).unwrap();

            // third signature, grace period over
            let signer = signers.get(2).unwrap().to_owned();
            let mut env = mock_env();
            env.block.height += 10;
            let res = do_sign(deps.as_mut(), env, session_id, &signer);

            assert_eq!(
                res.unwrap_err().to_string(),
                axelar_wasm_std::ContractError::from(ContractError::SigningSessionClosed {
                    session_id: session_id
                })
                .to_string()
            )
        }
    }

    #[test]
    fn submit_signature_wrong_session_id() {
        let (mut deps, ecdsa_subkey, _) = setup();
        do_authorize_caller(deps.as_mut(), Addr::unchecked(PROVER)).unwrap();
        do_start_signing_session(deps.as_mut(), PROVER, &ecdsa_subkey).unwrap();

        let invalid_session_id = Uint64::zero();
        let signer = ecdsa_test_data::signers().get(0).unwrap().to_owned();
        let res = do_sign(deps.as_mut(), mock_env(), invalid_session_id, &signer);

        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::SigningSessionNotFound {
                session_id: invalid_session_id
            })
            .to_string()
        );
    }

    #[test]
    fn query_signing_session() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        do_authorize_caller(deps.as_mut(), Addr::unchecked(PROVER)).unwrap();

        for (_key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(deps.as_mut(), PROVER, subkey).unwrap();

            do_sign(
                deps.as_mut(),
                mock_env(),
                session_id,
                signers.get(0).unwrap(),
            )
            .unwrap();

            let env = mock_env();
            let expected_completed_at = env.block.height;
            do_sign(deps.as_mut(), env, session_id, signers.get(1).unwrap()).unwrap();

            let msg = QueryMsg::GetMultisig { session_id };

            let res = query(deps.as_ref(), mock_env(), msg);
            assert!(res.is_ok());

            let query_res: Multisig = from_binary(&res.unwrap()).unwrap();
            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, session_id.into())
                .unwrap();
            let worker_set = WORKER_SETS
                .load(deps.as_ref().storage, session.worker_set_id.as_str())
                .unwrap();
            let signatures =
                load_session_signatures(deps.as_ref().storage, session.id.u64()).unwrap();

            assert_eq!(
                query_res.state,
                MultisigState::Completed {
                    completed_at: expected_completed_at
                }
            );
            assert_eq!(query_res.signers.len(), worker_set.signers.len());
            worker_set
                .signers
                .iter()
                .for_each(|(address, worker_set_signer)| {
                    let signer = query_res
                        .signers
                        .iter()
                        .find(|signer| signer.0.address == worker_set_signer.address)
                        .unwrap();

                    assert_eq!(signer.0.weight, Uint256::from(worker_set_signer.weight));
                    assert_eq!(
                        signer.0.pub_key,
                        worker_set.signers.get(address).unwrap().pub_key
                    );
                    assert_eq!(signer.1, signatures.get(address).cloned());
                });
        }
    }

    #[test]
    fn register_key() {
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
    fn update_key() {
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

    #[test]
    fn authorize_and_unauthorize_caller() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();

        // authorize
        do_authorize_caller(deps.as_mut(), Addr::unchecked(PROVER)).unwrap();

        for worker_set_id in [ecdsa_subkey.clone(), ed25519_subkey.clone()] {
            let res = do_start_signing_session(deps.as_mut(), PROVER, &worker_set_id);

            assert!(res.is_ok());
        }

        // unauthorize
        do_unauthorize_caller(deps.as_mut(), Addr::unchecked(PROVER)).unwrap();
        for worker_set_id in [ecdsa_subkey, ed25519_subkey] {
            let res = do_start_signing_session(deps.as_mut(), PROVER, &worker_set_id);

            assert_eq!(
                res.unwrap_err().to_string(),
                axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
                    + ": () not found"
            );
        }
    }

    #[test]
    fn authorize_caller_wrong_caller() {
        let mut deps = setup().0;

        let info = mock_info("user", &[]);
        let env = mock_env();

        let msg = ExecuteMsg::AuthorizeCaller {
            contract_address: Addr::unchecked(PROVER),
        };
        let res = execute(deps.as_mut(), env, info, msg);

        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
        );
    }

    #[test]
    fn unauthorize_caller_wrong_caller() {
        let mut deps = setup().0;

        let info = mock_info("user", &[]);
        let env = mock_env();

        let msg = ExecuteMsg::UnauthorizeCaller {
            contract_address: Addr::unchecked(PROVER),
        };
        let res = execute(deps.as_mut(), env, info, msg);

        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
        );
    }
}

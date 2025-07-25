use std::collections::HashMap;

use axelar_wasm_std::{address, killswitch, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult,
    Storage, Uint64,
};
use error_stack::{report, Report, ResultExt};
use itertools::Itertools;
use msgs_derive::ensure_permissions;
use router_api::ChainName;

use crate::events::Event;
use crate::msg::{ExecuteMsg, ExecuteMsgFromProxy, InstantiateMsg, QueryMsg};
use crate::state::{
    verifier_set, Config, CONFIG, SIGNING_SESSIONS, SIGNING_SESSION_COUNTER, VERIFIER_SETS,
};
use crate::types::{MsgToSign, MultisigState};
use crate::ContractError;

mod execute;
mod migrations;
mod query;

pub use migrations::{migrate, MigrateMsg};

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = address::validate_cosmwasm_address(deps.api, &msg.admin_address)?;
    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_address)?;

    permission_control::set_admin(deps.storage, &admin)?;
    permission_control::set_governance(deps.storage, &governance)?;

    killswitch::init(deps.storage, killswitch::State::Disengaged)?;

    let config = Config {
        rewards_contract: address::validate_cosmwasm_address(deps.api, &msg.rewards_address)?,
        block_expiry: msg.block_expiry,
        coordinator: msg.coordinator_address,
    };
    CONFIG.save(deps.storage, &config)?;

    SIGNING_SESSION_COUNTER.save(deps.storage, &Uint64::zero())?;

    Ok(Response::default())
}

#[ensure_permissions(proxy(coordinator = find_coordinator), direct(authorized = can_start_signing_session(&info.sender)))]
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg {
        ExecuteMsg::StartSigningSession {
            verifier_set_id,
            msg,
            chain_name,
            sig_verifier,
        } => {
            let sig_verifier = sig_verifier
                .map(|addr| address::validate_cosmwasm_address(deps.api, &addr))
                .transpose()?;
            execute::start_signing_session(
                deps,
                env,
                verifier_set_id,
                msg.into(),
                chain_name,
                sig_verifier,
            )
        }
        ExecuteMsg::SubmitSignature {
            session_id,
            signature,
        } => execute::submit_signature(deps, env, info, session_id, signature),
        ExecuteMsg::RegisterVerifierSet { verifier_set } => {
            execute::register_verifier_set(deps, verifier_set)
        }
        ExecuteMsg::RegisterPublicKey {
            public_key,
            signed_sender_address,
        } => execute::register_pub_key(deps, info, public_key, signed_sender_address),
        ExecuteMsg::AuthorizeCallers { contracts } => {
            let contracts = validate_contract_addresses(&deps, contracts)?;
            execute::authorize_callers(deps, contracts)
        }
        ExecuteMsg::UnauthorizeCallers { contracts } => {
            let contracts = validate_contract_addresses(&deps, contracts)?;
            execute::unauthorize_callers(deps, contracts)
        }
        ExecuteMsg::DisableSigning => execute::disable_signing(deps),
        ExecuteMsg::EnableSigning => execute::enable_signing(deps),
    }?
    .then(Ok)
}

fn validate_contract_addresses(
    deps: &DepsMut,
    contracts: HashMap<String, ChainName>,
) -> Result<HashMap<Addr, ChainName>, Report<address::Error>> {
    contracts
        .into_iter()
        .map(|(contract_address, chain_name)| {
            Ok((
                address::validate_cosmwasm_address(deps.api, &contract_address)?,
                chain_name,
            ))
        })
        .try_collect()
}

fn can_start_signing_session(
    sender: &Addr,
) -> impl FnOnce(&dyn Storage, &ExecuteMsg) -> error_stack::Result<Addr, permission_control::Error> + '_
{
    |storage, msg| match msg {
        ExecuteMsg::StartSigningSession { chain_name, .. } => {
            execute::require_authorized_caller(storage, sender, chain_name)
                .change_context(permission_control::Error::Unauthorized)
        }
        _ => Err(report!(permission_control::Error::WrongVariant)),
    }
}

fn find_coordinator(storage: &dyn Storage) -> error_stack::Result<Addr, ContractError> {
    Ok(CONFIG
        .load(storage)
        .map_err(|e| error_stack::report!(ContractError::from(e)))?
        .coordinator)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::Multisig { session_id } => to_json_binary(&query::multisig(deps, session_id)?)?,
        QueryMsg::VerifierSet { verifier_set_id } => {
            to_json_binary(&query::verifier_set(deps, verifier_set_id)?)?
        }
        QueryMsg::PublicKey {
            verifier_address,
            key_type,
        } => to_json_binary(&query::public_key(
            deps,
            address::validate_cosmwasm_address(deps.api, &verifier_address)?,
            key_type,
        )?)?,
        QueryMsg::IsCallerAuthorized {
            contract_address,
            chain_name,
        } => to_json_binary(&query::caller_authorized(
            deps,
            address::validate_cosmwasm_address(deps.api, &contract_address)?,
            chain_name,
        )?)?,
    }
    .then(Ok)
}

#[cfg(feature = "test")]
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::vec;

    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{from_json, Addr, Empty, OwnedDeps, WasmMsg};
    use k256::elliptic_curve::rand_core;
    use permission_control::Permission;
    use router_api::ChainName;
    use serde_json::from_str;

    use super::*;
    use crate::key::{KeyType, PublicKey, Signature};
    use crate::multisig::Multisig;
    use crate::state::load_session_signatures;
    use crate::test::common::{
        build_verifier_set, ecdsa_test_data, ed25519_test_data, signature_test_data, TestSigner,
    };
    use crate::types::MultisigState;
    use crate::verifier_set::VerifierSet;

    const INSTANTIATOR: &str = "inst";
    const PROVER: &str = "prover";
    const REWARDS_CONTRACT: &str = "rewards";
    const GOVERNANCE: &str = "governance";
    const ADMIN: &str = "admin";
    const COORDINATOR: &str = "coordinator";

    const SIGNATURE_BLOCK_EXPIRY: u64 = 100;

    fn do_instantiate(deps: DepsMut) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let api = MockApi::default();
        let instantiator = api.addr_make(INSTANTIATOR);
        let governance = api.addr_make(GOVERNANCE);
        let admin = api.addr_make(ADMIN);
        let rewards = api.addr_make(REWARDS_CONTRACT);
        let coordinator = api.addr_make(COORDINATOR);

        let info = message_info(&instantiator, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {
            governance_address: governance.into_string(),
            admin_address: admin.into_string(),
            rewards_address: rewards.into_string(),
            block_expiry: SIGNATURE_BLOCK_EXPIRY.try_into().unwrap(),
            coordinator_address: coordinator,
        };

        instantiate(deps, env, info, msg)
    }

    fn generate_verifier_set(
        key_type: KeyType,
        deps: DepsMut,
    ) -> Result<(Response, VerifierSet), axelar_wasm_std::error::ContractError> {
        let info = message_info(&MockApi::default().addr_make(PROVER), &[]);
        let env = mock_env();

        let signers = match key_type {
            KeyType::Ecdsa => ecdsa_test_data::signers(),
            KeyType::Ed25519 => ed25519_test_data::signers(),
        };

        let verifier_set = build_verifier_set(key_type, &signers);
        let msg = ExecuteMsg::RegisterVerifierSet {
            verifier_set: verifier_set.clone(),
        };

        execute(deps, env, info.clone(), msg.into()).map(|res| (res, verifier_set))
    }

    fn query_verifier_set(
        verifier_set_id: &str,
        deps: Deps,
    ) -> Result<Binary, axelar_wasm_std::error::ContractError> {
        let env = mock_env();
        query(
            deps,
            env,
            QueryMsg::VerifierSet {
                verifier_set_id: verifier_set_id.to_string(),
            },
        )
    }

    fn do_start_signing_session(
        deps: DepsMut,
        sender: Addr,
        verifier_set_id: &str,
        chain_name: ChainName,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let info = message_info(&sender, &[]);
        let env = mock_env();

        let message = ecdsa_test_data::message();
        let msg = ExecuteMsg::StartSigningSession {
            verifier_set_id: verifier_set_id.to_string(),
            msg: message.clone(),
            chain_name,
            sig_verifier: None,
        };
        execute(deps, env, info, msg.into())
    }

    fn do_sign(
        deps: DepsMut,
        env: Env,
        session_id: Uint64,
        signer: &TestSigner,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::SubmitSignature {
            session_id,
            signature: signer.signature.clone(),
        };
        execute(deps, env, message_info(&signer.address, &[]), msg.into())
    }

    fn do_register_key(
        deps: DepsMut,
        verifier: Addr,
        public_key: PublicKey,
        signed_sender_address: HexBinary,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::RegisterPublicKey {
            public_key,
            signed_sender_address,
        };
        execute(deps, mock_env(), message_info(&verifier, &[]), msg.into())
    }

    fn do_authorize_callers(
        deps: DepsMut,
        contracts: Vec<(Addr, ChainName)>,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let info = message_info(&MockApi::default().addr_make(GOVERNANCE), &[]);
        let env = mock_env();

        let msg = ExecuteMsg::AuthorizeCallers {
            contracts: contracts
                .into_iter()
                .map(|(addr, chain_name)| (addr.to_string(), chain_name))
                .collect(),
        };
        execute(deps, env, info, msg.into())
    }

    fn do_unauthorize_caller(
        deps: DepsMut,
        contracts: Vec<(Addr, ChainName)>,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let info = message_info(&MockApi::default().addr_make(GOVERNANCE), &[]);
        let env = mock_env();

        let msg = ExecuteMsg::UnauthorizeCallers {
            contracts: contracts
                .into_iter()
                .map(|(addr, chain_name)| (addr.to_string(), chain_name))
                .collect(),
        };
        execute(deps, env, info, msg.into())
    }

    fn do_disable_signing(
        deps: DepsMut,
        sender: Addr,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let info = message_info(&sender, &[]);
        let env = mock_env();

        let msg = ExecuteMsg::DisableSigning;
        execute(deps, env, info, msg.into())
    }

    fn do_enable_signing(
        deps: DepsMut,
        sender: Addr,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let info = message_info(&sender, &[]);
        let env = mock_env();

        let msg = ExecuteMsg::EnableSigning;
        execute(deps, env, info, msg.into())
    }

    fn query_registered_public_key(
        deps: Deps,
        verifier: Addr,
        key_type: KeyType,
    ) -> Result<Binary, axelar_wasm_std::error::ContractError> {
        let env = mock_env();
        query(
            deps,
            env,
            QueryMsg::PublicKey {
                verifier_address: verifier.to_string(),
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
        let verifier_set_ecdsa = generate_verifier_set(KeyType::Ecdsa, deps.as_mut())
            .unwrap()
            .1;
        let verifier_set_ed25519 = generate_verifier_set(KeyType::Ed25519, deps.as_mut())
            .unwrap()
            .1;
        let ecdsa_subkey = verifier_set_ecdsa.id();
        let ed25519_subkey = verifier_set_ed25519.id();

        (deps, ecdsa_subkey, ed25519_subkey)
    }

    // TODO: move to external crate?
    fn event_attribute<'a>(
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
    fn instantiation() {
        let mut deps = mock_dependencies();

        let res = do_instantiate(deps.as_mut());
        assert!(res.is_ok());
        assert_eq!(0, res.unwrap().messages.len());

        let session_counter = SIGNING_SESSION_COUNTER.load(deps.as_ref().storage).unwrap();

        assert_eq!(
            permission_control::sender_role(
                deps.as_ref().storage,
                &MockApi::default().addr_make(ADMIN)
            )
            .unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(
                deps.as_ref().storage,
                &MockApi::default().addr_make(GOVERNANCE)
            )
            .unwrap(),
            Permission::Governance.into()
        );

        assert_eq!(session_counter, Uint64::zero());
    }

    #[test]
    fn update_verifier_set() {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();

        let res = generate_verifier_set(KeyType::Ecdsa, deps.as_mut());
        assert!(res.is_ok());
        let verifier_set_1 = res.unwrap().1;
        let verifier_set_1_id = verifier_set_1.id();

        let res = generate_verifier_set(KeyType::Ed25519, deps.as_mut());
        assert!(res.is_ok());
        let verifier_set_2 = res.unwrap().1;
        let verifier_set_2_id = verifier_set_2.id();

        let res = query_verifier_set(&verifier_set_1.id(), deps.as_ref());
        assert!(res.is_ok());
        assert_eq!(verifier_set_1, from_json(res.unwrap()).unwrap());

        let res = query_verifier_set(&verifier_set_2.id(), deps.as_ref());
        assert!(res.is_ok());
        assert_eq!(verifier_set_2, from_json(res.unwrap()).unwrap());

        for (key_type, _) in [
            (KeyType::Ecdsa, verifier_set_1_id),
            (KeyType::Ed25519, verifier_set_2_id),
        ] {
            let res = generate_verifier_set(key_type, deps.as_mut());
            assert!(res.is_ok());
        }
    }

    #[test]
    fn start_signing_session() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        do_authorize_callers(
            deps.as_mut(),
            vec![(api.addr_make(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (i, subkey) in [ecdsa_subkey.clone(), ed25519_subkey.clone()]
            .into_iter()
            .enumerate()
        {
            let res = do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                &subkey,
                chain_name.clone(),
            );

            assert!(res.is_ok());

            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, i as u64 + 1)
                .unwrap();

            let verifier_set_id = subkey.to_string();
            let verifier_set = verifier_set(deps.as_ref().storage, &verifier_set_id).unwrap();
            let message = match subkey {
                _ if subkey == ecdsa_subkey => ecdsa_test_data::message(),
                _ if subkey == ed25519_subkey => ed25519_test_data::message(),
                _ => panic!("unexpected subkey"),
            };
            let signatures =
                load_session_signatures(deps.as_ref().storage, session.id.u64()).unwrap();

            assert_eq!(session.id, Uint64::from(i as u64 + 1));
            assert_eq!(session.verifier_set_id, verifier_set_id);
            assert_eq!(session.msg, message.clone().into());
            assert!(signatures.is_empty());
            assert_eq!(session.state, MultisigState::Pending);

            let res = res.unwrap();
            assert_eq!(res.data, Some(to_json_binary(&session.id).unwrap()));
            assert_eq!(res.events.len(), 1);

            let event = res.events.first().unwrap();
            assert_eq!(event.ty, "signing_started".to_string());
            assert_eq!(
                event_attribute(event, "session_id").unwrap(),
                session.id.to_string()
            );
            assert_eq!(
                event_attribute(event, "verifier_set_id").unwrap(),
                session.verifier_set_id
            );
            assert_eq!(
                verifier_set.pub_keys(),
                from_str(event_attribute(event, "pub_keys").unwrap()).unwrap()
            );
            assert_eq!(event_attribute(event, "msg").unwrap(), message.to_hex());
        }
    }

    #[test]
    fn start_signing_session_wrong_sender() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        do_authorize_callers(
            deps.as_mut(),
            vec![(MockApi::default().addr_make(PROVER), chain_name.clone())],
        )
        .unwrap();

        let sender = "someone else";

        for verifier_set_id in [ecdsa_subkey, ed25519_subkey] {
            let res = do_start_signing_session(
                deps.as_mut(),
                api.addr_make(sender),
                &verifier_set_id,
                chain_name.clone(),
            );

            assert!(res
                .unwrap_err()
                .to_string()
                .contains(&permission_control::Error::Unauthorized.to_string()));
        }
    }

    #[test]
    fn submit_signature() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        do_authorize_callers(
            deps.as_mut(),
            vec![(api.addr_make(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (key_type, verifier_set_id, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                verifier_set_id,
                chain_name.clone(),
            )
            .unwrap();

            let signer = signers.first().unwrap().to_owned();

            let expected_rewards_msg = WasmMsg::Execute {
                contract_addr: api.addr_make(REWARDS_CONTRACT).to_string(),
                msg: to_json_binary(&rewards::msg::ExecuteMsg::RecordParticipation {
                    chain_name: chain_name.clone(),
                    event_id: session_id.to_string().try_into().unwrap(),
                    verifier_address: signer.address.clone().into(),
                })
                .unwrap(),
                funds: vec![],
            }
            .into();

            let res = do_sign(deps.as_mut(), mock_env(), session_id, &signer);

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

            let event = res.events.first().unwrap();
            assert_eq!(event.ty, "signature_submitted".to_string());
            assert_eq!(
                event_attribute(event, "session_id").unwrap(),
                session_id.to_string()
            );
            assert_eq!(
                event_attribute(event, "participant").unwrap(),
                signer.address.into_string()
            );
            assert_eq!(
                event_attribute(event, "signature").unwrap(),
                signer.signature.to_hex()
            );
        }
    }

    #[test]
    fn submit_signature_completes_session() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        do_authorize_callers(
            deps.as_mut(),
            vec![(api.addr_make(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                subkey,
                chain_name.clone(),
            )
            .unwrap();

            let signer = signers.first().unwrap().to_owned();
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
                event_attribute(event, "session_id").unwrap(),
                session_id.to_string()
            );
        }
    }

    #[test]
    fn submit_signature_before_expiry() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        do_authorize_callers(
            deps.as_mut(),
            vec![(api.addr_make(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (_key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                subkey,
                chain_name.clone(),
            )
            .unwrap();

            let signer = signers.first().unwrap().to_owned();
            do_sign(deps.as_mut(), mock_env(), session_id, &signer).unwrap();

            // second signature
            let signer = signers.get(1).unwrap().to_owned();
            do_sign(deps.as_mut(), mock_env(), session_id, &signer).unwrap();

            // third signature
            let signer = signers.get(2).unwrap().to_owned();

            let expected_rewards_msg = WasmMsg::Execute {
                contract_addr: api.addr_make(REWARDS_CONTRACT).to_string(),
                msg: to_json_binary(&rewards::msg::ExecuteMsg::RecordParticipation {
                    chain_name: chain_name.clone(),
                    event_id: session_id.to_string().try_into().unwrap(),
                    verifier_address: signer.address.clone().into(),
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
            assert!(!res.events.iter().any(|e| e.ty == *"signing_completed")); // event is not re-emitted
        }
    }

    #[test]
    fn submit_signature_after_expiry() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;

        let chain_name: ChainName = "mock-chain".parse().unwrap();
        do_authorize_callers(
            deps.as_mut(),
            vec![(api.addr_make(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (_key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                subkey,
                chain_name.clone(),
            )
            .unwrap();

            let signer = signers.first().unwrap().to_owned();
            do_sign(deps.as_mut(), mock_env(), session_id, &signer).unwrap();

            // second signature
            let signer = signers.get(1).unwrap().to_owned();
            do_sign(deps.as_mut(), mock_env(), session_id, &signer).unwrap();

            // third signature, expiration block passed
            let signer = signers.get(2).unwrap().to_owned();
            let mut env = mock_env();
            env.block.height += 101;
            let res = do_sign(deps.as_mut(), env, session_id, &signer);

            assert_eq!(
                res.unwrap_err().to_string(),
                axelar_wasm_std::error::ContractError::from(ContractError::SigningSessionClosed {
                    session_id
                })
                .to_string()
            )
        }
    }

    #[test]
    fn submit_signature_wrong_session_id() {
        let (mut deps, ecdsa_subkey, _) = setup();
        let api = deps.api;
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        do_authorize_callers(
            deps.as_mut(),
            vec![(api.addr_make(PROVER), chain_name.clone())],
        )
        .unwrap();
        do_start_signing_session(
            deps.as_mut(),
            api.addr_make(PROVER),
            &ecdsa_subkey,
            chain_name.clone(),
        )
        .unwrap();

        let invalid_session_id = Uint64::zero();
        let signer = ecdsa_test_data::signers().first().unwrap().to_owned();
        let res = do_sign(deps.as_mut(), mock_env(), invalid_session_id, &signer);

        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::SigningSessionNotFound {
                session_id: invalid_session_id
            })
            .to_string()
        );
    }

    #[test]
    fn query_signing_session() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        do_authorize_callers(
            deps.as_mut(),
            vec![(api.addr_make(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (_key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                subkey,
                "mock-chain".parse().unwrap(),
            )
            .unwrap();

            do_sign(
                deps.as_mut(),
                mock_env(),
                session_id,
                signers.first().unwrap(),
            )
            .unwrap();

            let env = mock_env();
            let expected_completed_at = env.block.height;
            do_sign(deps.as_mut(), env, session_id, signers.get(1).unwrap()).unwrap();

            let msg = QueryMsg::Multisig { session_id };

            let res = query(deps.as_ref(), mock_env(), msg);
            assert!(res.is_ok());

            let query_res: Multisig = from_json(res.unwrap()).unwrap();
            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, session_id.into())
                .unwrap();
            let verifier_set = VERIFIER_SETS
                .load(deps.as_ref().storage, session.verifier_set_id.as_str())
                .unwrap();
            let signatures =
                load_session_signatures(deps.as_ref().storage, session.id.u64()).unwrap();

            assert_eq!(
                query_res.state,
                MultisigState::Completed {
                    completed_at: expected_completed_at
                }
            );
            assert_eq!(query_res.signatures, signatures);
            assert_eq!(query_res.verifier_set, verifier_set);
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
            .map(|signer| {
                (
                    signer.address.clone(),
                    signer.pub_key.clone(),
                    signer.signed_address.clone(),
                )
            })
            .collect::<Vec<(Addr, HexBinary, HexBinary)>>();

        for (addr, pub_key, signed_address) in &ecdsa_pub_keys {
            do_register_key(
                deps.as_mut(),
                addr.clone(),
                PublicKey::Ecdsa(pub_key.clone()),
                signed_address.clone(),
            )
            .unwrap();
        }

        // Register an ED25519 key
        let ed25519_signers = ed25519_test_data::signers();
        let ed25519_pub_keys = ed25519_signers
            .iter()
            .map(|signer| {
                (
                    signer.address.clone(),
                    signer.pub_key.clone(),
                    signer.signed_address.clone(),
                )
            })
            .collect::<Vec<(Addr, HexBinary, HexBinary)>>();

        for (addr, pub_key, signed_address) in &ed25519_pub_keys {
            do_register_key(
                deps.as_mut(),
                addr.clone(),
                PublicKey::Ed25519(pub_key.clone()),
                signed_address.clone(),
            )
            .unwrap();
        }

        // Test that we can query both keys
        for (key_type, expected_pub_keys) in [
            (KeyType::Ecdsa, ecdsa_pub_keys),
            (KeyType::Ed25519, ed25519_pub_keys),
        ] {
            let mut ret_pub_keys: Vec<PublicKey> = vec![];

            for (addr, _, _) in &expected_pub_keys {
                let res = query_registered_public_key(deps.as_ref(), addr.clone(), key_type);
                assert!(res.is_ok());
                ret_pub_keys.push(from_json(res.unwrap()).unwrap());
            }
            assert_eq!(
                expected_pub_keys
                    .into_iter()
                    .map(|(_, pk, _)| PublicKey::try_from((key_type, pk)).unwrap())
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

        signers.iter().for_each(|signer| {
            do_register_key(
                deps.as_mut(),
                signer.address.clone(),
                PublicKey::Ecdsa(signer.pub_key.clone()),
                signer.signed_address.clone(),
            )
            .unwrap();
        });

        // Update ECDSA key
        let new_ecdsa_signing_key = k256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let new_signer = ecdsa_test_data::new(
            signers.first().unwrap().address.clone(),
            new_ecdsa_signing_key.clone(),
        );
        do_register_key(
            deps.as_mut(),
            new_signer.address.clone(),
            PublicKey::Ecdsa(new_signer.pub_key.clone()),
            new_signer.signed_address.clone(),
        )
        .unwrap();

        let res = query_registered_public_key(deps.as_ref(), new_signer.address, KeyType::Ecdsa);
        assert!(res.is_ok());
        assert_eq!(
            PublicKey::try_from((
                KeyType::Ecdsa,
                new_ecdsa_signing_key
                    .verifying_key()
                    .to_sec1_bytes()
                    .to_vec()
                    .into()
            ))
            .unwrap(),
            from_json::<PublicKey>(&res.unwrap()).unwrap()
        );

        // Register an ED25519 key, it should not affect our ECDSA key
        let new_ed25519_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let new_signer = ed25519_test_data::new(
            signers.first().unwrap().address.clone(),
            new_ed25519_signing_key.clone(),
        );
        do_register_key(
            deps.as_mut(),
            new_signer.address.clone(),
            PublicKey::Ed25519(new_signer.pub_key.clone()),
            new_signer.signed_address.clone(),
        )
        .unwrap();

        let res = query_registered_public_key(
            deps.as_ref(),
            new_signer.address.clone(),
            KeyType::Ed25519,
        );
        assert!(res.is_ok());
        assert_eq!(
            PublicKey::try_from((
                KeyType::Ed25519,
                new_ed25519_signing_key
                    .verifying_key()
                    .to_bytes()
                    .to_vec()
                    .into()
            ))
            .unwrap(),
            from_json::<PublicKey>(&res.unwrap()).unwrap()
        );

        let res = query_registered_public_key(deps.as_ref(), new_signer.address, KeyType::Ecdsa);
        assert!(res.is_ok());
        assert_eq!(
            PublicKey::try_from((
                KeyType::Ecdsa,
                new_ecdsa_signing_key
                    .verifying_key()
                    .to_sec1_bytes()
                    .to_vec()
                    .into()
            ))
            .unwrap(),
            from_json::<PublicKey>(&res.unwrap()).unwrap()
        );
    }

    #[test]
    fn should_fail_register_key_if_signature_invalid() {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();

        // Ecdsa
        let signers = ecdsa_test_data::signers();
        let signer1 = signers.first().unwrap();
        let signer2 = signers.last().unwrap();

        let res = do_register_key(
            deps.as_mut(),
            signer1.address.clone(),
            PublicKey::Ecdsa(signer1.pub_key.clone()),
            signer2.signed_address.clone(),
        );
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(
                ContractError::InvalidPublicKeyRegistrationSignature
            )
            .to_string()
        );

        // Ed25519
        let signers = ed25519_test_data::signers();
        let signer1 = signers.first().unwrap();
        let signer2 = signers.last().unwrap();

        let res = do_register_key(
            deps.as_mut(),
            signer1.address.clone(),
            PublicKey::Ed25519(signer1.pub_key.clone()),
            signer2.signed_address.clone(),
        );
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(
                ContractError::InvalidPublicKeyRegistrationSignature
            )
            .to_string()
        );
    }

    #[test]
    fn should_fail_duplicate_public_key_registration() {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();

        // Ecdsa
        let signer = ecdsa_test_data::signers().pop().unwrap();

        do_register_key(
            deps.as_mut(),
            signer.address.clone(),
            PublicKey::Ecdsa(signer.pub_key.clone()),
            signer.signed_address.clone(),
        )
        .unwrap();

        let res = do_register_key(
            deps.as_mut(),
            signer.address.clone(),
            PublicKey::Ecdsa(signer.pub_key.clone()),
            signer.signed_address.clone(),
        );

        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::DuplicatePublicKey)
                .to_string()
        );
    }

    #[test]
    fn authorize_and_unauthorize_callers() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;
        let prover_address = api.addr_make(PROVER);
        let chain_name: ChainName = "mock-chain".parse().unwrap();

        // authorize
        do_authorize_callers(
            deps.as_mut(),
            vec![(prover_address.clone(), chain_name.clone())],
        )
        .unwrap();

        for verifier_set_id in [ecdsa_subkey.clone(), ed25519_subkey.clone()] {
            let res = do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                &verifier_set_id,
                chain_name.clone(),
            );

            assert!(res.is_ok());
        }

        let caller_authorization_status =
            query::caller_authorized(deps.as_ref(), prover_address.clone(), chain_name.clone())
                .unwrap();
        assert!(caller_authorization_status);

        // unauthorize
        do_unauthorize_caller(
            deps.as_mut(),
            vec![(prover_address.clone(), chain_name.clone())],
        )
        .unwrap();
        for verifier_set_id in [ecdsa_subkey, ed25519_subkey] {
            let res = do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                &verifier_set_id,
                chain_name.clone(),
            );

            assert!(res
                .unwrap_err()
                .to_string()
                .contains(&permission_control::Error::Unauthorized.to_string()));
        }

        let caller_authorization_status =
            query::caller_authorized(deps.as_ref(), prover_address, chain_name.clone()).unwrap();
        assert!(!caller_authorization_status);
    }

    #[test]
    fn authorize_and_unauthorize_many_callers() {
        let (mut deps, _, _) = setup();

        let contracts = vec![
            (deps.api.addr_make("addr1"), "chain1".parse().unwrap()),
            (deps.api.addr_make("addr2"), "chain2".parse().unwrap()),
            (deps.api.addr_make("addr3"), "chain3".parse().unwrap()),
        ];
        do_authorize_callers(deps.as_mut(), contracts.clone()).unwrap();
        assert!(contracts
            .iter()
            .all(|(addr, chain_name)| query::caller_authorized(
                deps.as_ref(),
                addr.clone(),
                chain_name.clone()
            )
            .unwrap()));
        let (authorized, unauthorized) = contracts.split_at(1);
        do_unauthorize_caller(deps.as_mut(), unauthorized.to_vec()).unwrap();
        assert!(unauthorized
            .iter()
            .all(|(addr, chain_name)| !query::caller_authorized(
                deps.as_ref(),
                addr.clone(),
                chain_name.clone()
            )
            .unwrap()));
        assert!(authorized
            .iter()
            .all(|(addr, chain_name)| query::caller_authorized(
                deps.as_ref(),
                addr.clone(),
                chain_name.clone()
            )
            .unwrap()));
    }

    #[test]
    fn authorize_caller_wrong_caller() {
        let mut deps = setup().0;

        let info = message_info(&deps.api.addr_make("user"), &[]);
        let env = mock_env();

        let msg = ExecuteMsg::AuthorizeCallers {
            contracts: HashMap::from([(
                deps.api.addr_make(PROVER).to_string(),
                "mock-chain".parse().unwrap(),
            )]),
        };
        let res = execute(deps.as_mut(), env, info, msg.into());

        assert_eq!(
            res.unwrap_err().to_string(),
            permission_control::Error::PermissionDenied {
                expected: Permission::Governance.into(),
                actual: Permission::NoPrivilege.into()
            }
            .to_string()
        );
    }

    #[test]
    fn unauthorize_caller_wrong_caller() {
        let mut deps = setup().0;

        let info = message_info(&deps.api.addr_make("user"), &[]);
        let env = mock_env();

        let msg = ExecuteMsg::UnauthorizeCallers {
            contracts: HashMap::from([(
                deps.api.addr_make(PROVER).to_string(),
                "mock-chain".parse().unwrap(),
            )]),
        };
        let res = execute(deps.as_mut(), env, info, msg.into());

        assert_eq!(
            res.unwrap_err().to_string(),
            permission_control::Error::PermissionDenied {
                expected: Permission::Elevated.into(),
                actual: Permission::NoPrivilege.into()
            }
            .to_string()
        );
    }

    #[test]
    fn disable_enable_signing() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;
        let prover_address = api.addr_make(PROVER);
        let chain_name: ChainName = "mock-chain".parse().unwrap();

        // authorize
        do_authorize_callers(
            deps.as_mut(),
            vec![(prover_address.clone(), chain_name.clone())],
        )
        .unwrap();

        do_disable_signing(deps.as_mut(), api.addr_make(ADMIN)).unwrap();

        for verifier_set_id in [ecdsa_subkey.clone(), ed25519_subkey.clone()] {
            let res = do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                &verifier_set_id,
                chain_name.clone(),
            );

            assert_eq!(
                res.unwrap_err().to_string(),
                ContractError::SigningDisabled.to_string()
            );
        }

        do_enable_signing(deps.as_mut(), api.addr_make(ADMIN)).unwrap();

        for verifier_set_id in [ecdsa_subkey.clone(), ed25519_subkey.clone()] {
            let res = do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                &verifier_set_id,
                "mock-chain".parse().unwrap(),
            );

            assert!(res.is_ok());
        }
    }

    #[test]
    fn disable_signing_after_session_creation() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;
        let chain_name: ChainName = "mock-chain".parse().unwrap();
        do_authorize_callers(
            deps.as_mut(),
            vec![(api.addr_make(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (_, verifier_set_id, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey)
        {
            do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                verifier_set_id,
                chain_name.clone(),
            )
            .unwrap();

            do_disable_signing(deps.as_mut(), api.addr_make(ADMIN)).unwrap();

            let signer = signers.first().unwrap().to_owned();

            let res = do_sign(deps.as_mut(), mock_env(), session_id, &signer);

            assert_eq!(
                res.unwrap_err().to_string(),
                ContractError::SigningDisabled.to_string()
            );

            do_enable_signing(deps.as_mut(), api.addr_make(ADMIN)).unwrap();
            assert!(do_sign(deps.as_mut(), mock_env(), session_id, &signer).is_ok());
        }
    }

    #[test]
    fn disable_enable_signing_has_correct_permissions() {
        let mut deps = setup().0;
        let api = deps.api;

        assert!(do_disable_signing(deps.as_mut(), api.addr_make("user1")).is_err());
        assert!(do_disable_signing(deps.as_mut(), api.addr_make(ADMIN)).is_ok());
        assert!(do_enable_signing(deps.as_mut(), api.addr_make("user")).is_err());
        assert!(do_enable_signing(deps.as_mut(), api.addr_make(ADMIN)).is_ok());
        assert!(do_disable_signing(deps.as_mut(), api.addr_make(GOVERNANCE)).is_ok());
        assert!(do_enable_signing(deps.as_mut(), api.addr_make(GOVERNANCE)).is_ok());
    }

    #[test]
    fn start_signing_session_wrong_chain() {
        let (mut deps, ecdsa_subkey, ed25519_subkey) = setup();
        let api = deps.api;

        let chain_name: ChainName = "mock-chain".parse().unwrap();
        do_authorize_callers(
            deps.as_mut(),
            vec![(api.addr_make(PROVER), chain_name.clone())],
        )
        .unwrap();

        let wrong_chain_name: ChainName = "some-other-chain".parse().unwrap();

        for verifier_set_id in [ecdsa_subkey, ed25519_subkey] {
            let res = do_start_signing_session(
                deps.as_mut(),
                api.addr_make(PROVER),
                &verifier_set_id,
                wrong_chain_name.clone(),
            );

            assert!(res.unwrap_err().to_string().contains(
                &ContractError::WrongChainName {
                    expected: chain_name.clone()
                }
                .to_string()
            ));
        }
    }
}

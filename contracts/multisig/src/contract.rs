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
    let coordinator = address::validate_cosmwasm_address(deps.api, &msg.coordinator_address)?;

    permission_control::set_admin(deps.storage, &admin)?;
    permission_control::set_governance(deps.storage, &governance)?;

    killswitch::init(deps.storage, killswitch::State::Disengaged)?;

    let config = Config {
        rewards_contract: address::validate_cosmwasm_address(deps.api, &msg.rewards_address)?,
        block_expiry: msg.block_expiry,
        coordinator,
    };
    CONFIG.save(deps.storage, &config)?;

    SIGNING_SESSION_COUNTER.save(deps.storage, &Uint64::zero())?;

    Ok(Response::default())
}

#[ensure_permissions(proxy(coordinator = find_coordinator), direct(authorized = can_start_signing_session))]
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
            let contracts = contracts
                .into_iter()
                .map(|(addr, chain_name)| {
                    address::validate_cosmwasm_address(deps.api, &addr)
                        .map(|validated_addr| (validated_addr, chain_name))
                })
                .collect::<Result<HashMap<Addr, ChainName>, _>>()?;

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
    contracts: Vec<String>,
) -> Result<Vec<Addr>, Report<address::Error>> {
    contracts
        .into_iter()
        .map(|contract_address| address::validate_cosmwasm_address(deps.api, &contract_address))
        .try_collect()
}

fn can_start_signing_session(
    storage: &dyn Storage,
    sender_addr: &Addr,
    msg: &ExecuteMsg,
) -> error_stack::Result<bool, permission_control::Error> {
    match msg {
        ExecuteMsg::StartSigningSession { chain_name, .. } => {
            Ok(
                query::caller_authorized(storage, sender_addr.clone(), chain_name.clone())
                    .change_context(permission_control::Error::Unauthorized)?,
            )
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
            deps.storage,
            address::validate_cosmwasm_address(deps.api, &contract_address)?,
            chain_name,
        )?)?,
        QueryMsg::AuthorizedCaller { chain_name } => {
            to_json_binary(&query::prover_for_chain(deps, chain_name)?)?
        }
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
    use router_api::{chain_name, cosmos_addr, ChainName};
    use serde_json::from_str;

    use super::*;
    use crate::key::{KeyType, PublicKey, Signature};
    use crate::multisig::Multisig;
    use crate::state::load_session_signatures;
    use crate::test::common::{
        aleo_schnorr_test_data, build_verifier_set, ecdsa_test_data, ed25519_test_data, signature_test_data, VerifierSetId, TestSigner
    };
    use crate::types::MultisigState;
    use crate::verifier_set::VerifierSet;

    const INSTANTIATOR: &str = "inst";
    const PROVER: &str = "prover";
    const REWARDS_CONTRACT: &str = "rewards";
    const GOVERNANCE: &str = "governance";
    const ADMIN: &str = "admin";
    const COORDINATOR: &str = "coordinator";
    const MOCK_CHAIN: &str = "mock-chain";
    const ALEO_SIGNATURE_VERIFIER: &str = "aleo-signature-verifier";

    const SIGNATURE_BLOCK_EXPIRY: u64 = 100;

    fn do_instantiate(deps: DepsMut) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let instantiator = cosmos_addr!(INSTANTIATOR);
        let governance = cosmos_addr!(GOVERNANCE);
        let admin = cosmos_addr!(ADMIN);
        let rewards = cosmos_addr!(REWARDS_CONTRACT);
        let coordinator = cosmos_addr!(COORDINATOR);

        let info = message_info(&instantiator, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {
            governance_address: governance.into_string(),
            admin_address: admin.into_string(),
            rewards_address: rewards.into_string(),
            block_expiry: SIGNATURE_BLOCK_EXPIRY.try_into().unwrap(),
            coordinator_address: coordinator.to_string(),
        };

        instantiate(deps, env, info, msg)
    }

    fn setup_aleo_sig_verify(deps: DepsMut) -> Result<Addr, axelar_wasm_std::error::ContractError> {
        let instantiator = cosmos_addr!(INSTANTIATOR);
        let info = message_info(&instantiator, &[]);
        let env = mock_env();

        // Deploy multisig-aleo contract
        let aleo_msg = multisig_aleo::msg::InstantiateMsg {
            network: aleo_network_config::network::NetworkConfig::TestnetV0,
        };

        multisig_aleo::contract::instantiate(deps, env, info, aleo_msg)?;

        // Return the deployed contract address
        Ok(cosmos_addr!(ALEO_SIGNATURE_VERIFIER))
    }

    fn generate_verifier_set(
        key_type: KeyType,
        deps: DepsMut,
    ) -> Result<(Response, VerifierSet), axelar_wasm_std::error::ContractError> {
        let info = message_info(&cosmos_addr!(PROVER), &[]);
        let env = mock_env();

        let signers = match key_type {
            KeyType::Ecdsa => ecdsa_test_data::signers(),
            KeyType::Ed25519 => ed25519_test_data::signers(),
            KeyType::AleoSchnorr => aleo_schnorr_test_data::signers(),
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
        verifier_set_id: &VerifierSetId,
        chain_name: ChainName,
        sig_verifier: Option<String>,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let info = message_info(&sender, &[]);
        let env = mock_env();

        let msg = match verifier_set_id {
            VerifierSetId::Ecdsa(_) => ecdsa_test_data::message(),
            VerifierSetId::Ed25519(_) => ed25519_test_data::message(),
            VerifierSetId::AleoSchnorr(_) => aleo_schnorr_test_data::message(),
        };

        let msg = ExecuteMsg::StartSigningSession {
            verifier_set_id: verifier_set_id.id().to_string(),
            msg,
            chain_name,
            sig_verifier,
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
        let info = message_info(&cosmos_addr!(GOVERNANCE), &[]);
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
        let info = message_info(&cosmos_addr!(GOVERNANCE), &[]);
        let env = mock_env();

        let msg = ExecuteMsg::UnauthorizeCallers {
            contracts: contracts
                .into_iter()
                .map(|(addr, _)| addr.to_string())
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
        VerifierSetId, // ECDSA verify address
        VerifierSetId, // Ed25519 verify address
        VerifierSetId, // Aleo Schnorr verify address
        Addr,   // Aleo Schnorr validate address
    ) {
        let mut deps = mock_dependencies();
        do_instantiate(deps.as_mut()).unwrap();

        let mut aleo_sig_deps = mock_dependencies();
        let aleo_sig_verify_addr = setup_aleo_sig_verify(aleo_sig_deps.as_mut()).unwrap();

        let verifier_set_ecdsa = generate_verifier_set(KeyType::Ecdsa, deps.as_mut())
            .unwrap()
            .1;
        let verifier_set_ed25519 = generate_verifier_set(KeyType::Ed25519, deps.as_mut())
            .unwrap()
            .1;
        let verifier_set_aleo_schnorr = generate_verifier_set(KeyType::AleoSchnorr, deps.as_mut())
            .unwrap()
            .1;
        let ecdsa_subkey = verifier_set_ecdsa.id();
        let ed25519_subkey = verifier_set_ed25519.id();
        let aleo_schnorr_subkey = verifier_set_aleo_schnorr.id();

        (
            deps,
            VerifierSetId::Ecdsa(ecdsa_subkey),
            VerifierSetId::Ed25519(ed25519_subkey),
            VerifierSetId::AleoSchnorr(aleo_schnorr_subkey),
            aleo_sig_verify_addr,
        )
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
            permission_control::sender_role(deps.as_ref().storage, &cosmos_addr!(ADMIN)).unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &cosmos_addr!(GOVERNANCE))
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

        let res = generate_verifier_set(KeyType::AleoSchnorr, deps.as_mut());
        assert!(res.is_ok());
        let verifier_set_3 = res.unwrap().1;
        let verifier_set_3_id = verifier_set_3.id();

        let res = query_verifier_set(&verifier_set_1.id(), deps.as_ref());
        assert!(res.is_ok());
        assert_eq!(verifier_set_1, from_json(res.unwrap()).unwrap());

        let res = query_verifier_set(&verifier_set_2.id(), deps.as_ref());
        assert!(res.is_ok());
        assert_eq!(verifier_set_2, from_json(res.unwrap()).unwrap());

        for (key_type, _) in [
            (KeyType::Ecdsa, verifier_set_1_id),
            (KeyType::Ed25519, verifier_set_2_id),
            (KeyType::AleoSchnorr, verifier_set_3_id),
        ] {
            let res = generate_verifier_set(key_type, deps.as_mut());
            assert!(res.is_ok());
        }
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn start_signing_session() {
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, _) = setup();
        let chain_name = chain_name!(MOCK_CHAIN);
        do_authorize_callers(
            deps.as_mut(),
            vec![(cosmos_addr!(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (i, subkey) in [&ecdsa_subkey, &ed25519_subkey, &aleo_schnorr_subkey]
            .into_iter()
            .enumerate()
        {
            let res = do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                subkey,
                chain_name.clone(),
                None,
            );

            assert!(res.is_ok());

            let session = SIGNING_SESSIONS
                .load(deps.as_ref().storage, i as u64 + 1)
                .unwrap();

            let verifier_set_id = subkey.id();
            let verifier_set = verifier_set(deps.as_ref().storage, &verifier_set_id).unwrap();
            let message = match subkey {
                VerifierSetId::Ecdsa(_) => ecdsa_test_data::message(),
                VerifierSetId::Ed25519(_) => ed25519_test_data::message(),
                VerifierSetId::AleoSchnorr(_) => aleo_schnorr_test_data::message(),
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
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, _) = setup();
        let chain_name = chain_name!(MOCK_CHAIN);
        do_authorize_callers(
            deps.as_mut(),
            vec![(cosmos_addr!(PROVER), chain_name.clone())],
        )
        .unwrap();

        for verifier_set_id in [&ecdsa_subkey, &ed25519_subkey, &aleo_schnorr_subkey] {
            let res = do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!("someone else"),
                &verifier_set_id,
                chain_name.clone(),
                None,
            );

            assert!(res.unwrap_err().to_string().contains(
                &permission_control::Error::SpecificPermissionDenied {
                    roles: vec![String::from("authorized")],
                }
                .to_string()
            ));
        }
    }

    #[test]
    fn submit_signature() {
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, aleo_sig_addr) = setup();
        let chain_name = chain_name!(MOCK_CHAIN);
        do_authorize_callers(
            deps.as_mut(),
            vec![(cosmos_addr!(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (key_type, verifier_set_id, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey, &aleo_schnorr_subkey)
        {
            let sig_verifier =
                matches!(key_type, KeyType::AleoSchnorr).then_some(aleo_sig_addr.to_string());

            do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                verifier_set_id,
                chain_name.clone(),
                sig_verifier,
            )
            .unwrap();

            let signer = signers.first().unwrap().to_owned();

            let expected_rewards_msg = WasmMsg::Execute {
                contract_addr: cosmos_addr!(REWARDS_CONTRACT).to_string(),
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
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, aleo_sig_addr) = setup();
        let chain_name = chain_name!(MOCK_CHAIN);
        do_authorize_callers(
            deps.as_mut(),
            vec![(cosmos_addr!(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey, &aleo_schnorr_subkey)
        {
            let sig_verifier =
                matches!(key_type, KeyType::AleoSchnorr).then_some(aleo_sig_addr.to_string());

            do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                subkey,
                chain_name.clone(),
                sig_verifier,
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
    #[allow(clippy::arithmetic_side_effects)]
    fn submit_signature_before_expiry() {
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, aleo_sig_addr) = setup();
        let chain_name = chain_name!(MOCK_CHAIN);
        do_authorize_callers(
            deps.as_mut(),
            vec![(cosmos_addr!(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey, &aleo_schnorr_subkey)
        {
            let sig_verifier =
                matches!(key_type, KeyType::AleoSchnorr).then_some(aleo_sig_addr.to_string());

            do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                subkey,
                chain_name.clone(),
                sig_verifier,
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
                contract_addr: cosmos_addr!(REWARDS_CONTRACT).to_string(),
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
    #[allow(clippy::arithmetic_side_effects)]
    fn submit_signature_after_expiry() {
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, aleo_sig_addr) = setup();

        let chain_name = chain_name!(MOCK_CHAIN);
        do_authorize_callers(
            deps.as_mut(),
            vec![(cosmos_addr!(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey, &aleo_schnorr_subkey)
        {
            let sig_verifier =
                matches!(key_type, KeyType::AleoSchnorr).then_some(aleo_sig_addr.to_string());

            do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                subkey,
                chain_name.clone(),
                sig_verifier,
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
        let (mut deps, ecdsa_subkey, _, _, _) = setup();
        let chain_name = chain_name!(MOCK_CHAIN);
        do_authorize_callers(
            deps.as_mut(),
            vec![(cosmos_addr!(PROVER), chain_name.clone())],
        )
        .unwrap();
        do_start_signing_session(
            deps.as_mut(),
            cosmos_addr!(PROVER),
            &ecdsa_subkey,
            chain_name.clone(),
            None,
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
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, aleo_sig_addr) = setup();
        let chain_name = chain_name!(MOCK_CHAIN);
        do_authorize_callers(
            deps.as_mut(),
            vec![(cosmos_addr!(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (key_type, subkey, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey, &aleo_schnorr_subkey)
        {
            let sig_verifier =
                matches!(key_type, KeyType::AleoSchnorr).then_some(aleo_sig_addr.to_string());

            do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                subkey,
                chain_name!(MOCK_CHAIN),
                sig_verifier,
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
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, _) = setup();
        let prover_address = cosmos_addr!(PROVER);
        let chain_name = chain_name!(MOCK_CHAIN);

        // authorize
        do_authorize_callers(
            deps.as_mut(),
            vec![(prover_address.clone(), chain_name.clone())],
        )
        .unwrap();

        for verifier_set_id in [
            ecdsa_subkey.clone(),
            ed25519_subkey.clone(),
            aleo_schnorr_subkey.clone(),
        ] {
            let res = do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                &verifier_set_id,
                chain_name.clone(),
                None,
            );

            assert!(res.is_ok());
        }

        let caller_authorization_status =
            query::caller_authorized(&deps.storage, prover_address.clone(), chain_name.clone())
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
                cosmos_addr!(PROVER),
                &verifier_set_id,
                chain_name.clone(),
                None,
            );

            assert!(res.unwrap_err().to_string().contains(
                &permission_control::Error::SpecificPermissionDenied {
                    roles: vec![String::from("authorized")],
                }
                .to_string()
            ));
        }

        let caller_authorization_status =
            query::caller_authorized(&deps.storage, prover_address, chain_name.clone()).unwrap();
        assert!(!caller_authorization_status);
    }

    #[test]
    fn authorize_and_unauthorize_many_callers() {
        let (mut deps, _, _, _, _) = setup();

        let contracts = vec![
            (cosmos_addr!("addr1"), chain_name!("chain1")),
            (cosmos_addr!("addr2"), chain_name!("chain2")),
            (cosmos_addr!("addr3"), chain_name!("chain3")),
        ];
        do_authorize_callers(deps.as_mut(), contracts.clone()).unwrap();
        assert!(contracts
            .iter()
            .all(|(addr, chain_name)| query::caller_authorized(
                &deps.storage,
                addr.clone(),
                chain_name.clone()
            )
            .unwrap()));
        let (authorized, unauthorized) = contracts.split_at(1);
        do_unauthorize_caller(deps.as_mut(), unauthorized.to_vec()).unwrap();
        assert!(unauthorized
            .iter()
            .all(|(addr, chain_name)| !query::caller_authorized(
                &deps.storage,
                addr.clone(),
                chain_name.clone()
            )
            .unwrap()));
        assert!(authorized
            .iter()
            .all(|(addr, chain_name)| query::caller_authorized(
                &deps.storage,
                addr.clone(),
                chain_name.clone()
            )
            .unwrap()));
    }

    #[test]
    fn authorize_caller_wrong_caller() {
        let mut deps = setup().0;

        let info = message_info(&cosmos_addr!("user"), &[]);
        let env = mock_env();

        let msg = ExecuteMsg::AuthorizeCallers {
            contracts: HashMap::from([(cosmos_addr!(PROVER).to_string(), chain_name!(MOCK_CHAIN))]),
        };
        let res = execute(deps.as_mut(), env, info, msg.into());

        assert_eq!(
            res.unwrap_err().to_string(),
            permission_control::Error::GeneralPermissionDenied {
                expected: Permission::Governance.into(),
                actual: Permission::NoPrivilege.into()
            }
            .to_string()
        );
    }

    #[test]
    fn unauthorize_caller_wrong_caller() {
        let mut deps = setup().0;

        let info = message_info(&cosmos_addr!("user"), &[]);
        let env = mock_env();

        let msg = ExecuteMsg::UnauthorizeCallers {
            contracts: vec![cosmos_addr!(PROVER).to_string()],
        };
        let res = execute(deps.as_mut(), env, info, msg.into());

        assert_eq!(
            res.unwrap_err().to_string(),
            permission_control::Error::GeneralPermissionDenied {
                expected: Permission::Elevated.into(),
                actual: Permission::NoPrivilege.into()
            }
            .to_string()
        );
    }

    #[test]
    fn disable_enable_signing() {
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, _) = setup();
        let prover_address = cosmos_addr!(PROVER);
        let chain_name = chain_name!(MOCK_CHAIN);

        // authorize
        do_authorize_callers(
            deps.as_mut(),
            vec![(prover_address.clone(), chain_name.clone())],
        )
        .unwrap();

        do_disable_signing(deps.as_mut(), cosmos_addr!(ADMIN)).unwrap();

        for verifier_set_id in [
            ecdsa_subkey.clone(),
            ed25519_subkey.clone(),
            aleo_schnorr_subkey.clone(),
        ] {
            let res = do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                &verifier_set_id,
                chain_name.clone(),
                None,
            );

            assert_eq!(
                res.unwrap_err().to_string(),
                ContractError::SigningDisabled.to_string()
            );
        }

        do_enable_signing(deps.as_mut(), cosmos_addr!(ADMIN)).unwrap();

        for verifier_set_id in [ecdsa_subkey.clone(), ed25519_subkey.clone()] {
            let res = do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                &verifier_set_id,
                chain_name!(MOCK_CHAIN),
                None,
            );

            assert!(res.is_ok());
        }
    }

    #[test]
    fn disable_signing_after_session_creation() {
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, aleo_sig_addr) = setup();
        let chain_name = chain_name!(MOCK_CHAIN);
        do_authorize_callers(
            deps.as_mut(),
            vec![(cosmos_addr!(PROVER), chain_name.clone())],
        )
        .unwrap();

        for (key_type, verifier_set_id, signers, session_id) in
            signature_test_data(&ecdsa_subkey, &ed25519_subkey, &aleo_schnorr_subkey)
        {
            let sig_verifier =
                matches!(key_type, KeyType::AleoSchnorr).then_some(aleo_sig_addr.to_string());

            do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                verifier_set_id,
                chain_name.clone(),
                sig_verifier,
            )
            .unwrap();

            do_disable_signing(deps.as_mut(), cosmos_addr!(ADMIN)).unwrap();

            let signer = signers.first().unwrap().to_owned();

            let res = do_sign(deps.as_mut(), mock_env(), session_id, &signer);

            assert_eq!(
                res.unwrap_err().to_string(),
                ContractError::SigningDisabled.to_string()
            );

            do_enable_signing(deps.as_mut(), cosmos_addr!(ADMIN)).unwrap();
            assert!(do_sign(deps.as_mut(), mock_env(), session_id, &signer).is_ok());
        }
    }

    #[test]
    fn disable_enable_signing_has_correct_permissions() {
        let mut deps = setup().0;

        assert!(do_disable_signing(deps.as_mut(), cosmos_addr!("user1")).is_err());
        assert!(do_disable_signing(deps.as_mut(), cosmos_addr!(ADMIN)).is_ok());
        assert!(do_enable_signing(deps.as_mut(), cosmos_addr!("user")).is_err());
        assert!(do_enable_signing(deps.as_mut(), cosmos_addr!(ADMIN)).is_ok());
        assert!(do_disable_signing(deps.as_mut(), cosmos_addr!(GOVERNANCE)).is_ok());
        assert!(do_enable_signing(deps.as_mut(), cosmos_addr!(GOVERNANCE)).is_ok());
    }

    #[test]
    fn start_signing_session_wrong_chain() {
        let (mut deps, ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey, _) = setup();
        let chain_name = chain_name!(MOCK_CHAIN);
        do_authorize_callers(
            deps.as_mut(),
            vec![(cosmos_addr!(PROVER), chain_name.clone())],
        )
        .unwrap();

        let wrong_chain_name = chain_name!("some-other-chain");

        for verifier_set_id in [ecdsa_subkey, ed25519_subkey, aleo_schnorr_subkey] {
            let res = do_start_signing_session(
                deps.as_mut(),
                cosmos_addr!(PROVER),
                &verifier_set_id,
                wrong_chain_name.clone(),
                None,
            );

            assert!(res.unwrap_err().to_string().contains(
                &permission_control::Error::SpecificPermissionDenied {
                    roles: vec![String::from("authorized")],
                }
                .to_string()
            ));
        }
    }

    #[test]
    fn query_authorized_callers_for_chains_succeeds() {
        let (mut deps, _, _) = setup();

        let contracts = vec![
            (cosmos_addr!("addr1"), chain_name!("chain1")),
            (cosmos_addr!("addr2"), chain_name!("chain2")),
        ];
        do_authorize_callers(deps.as_mut(), contracts.clone()).unwrap();

        let res = query::prover_for_chain(deps.as_ref(), chain_name!("chain1"));
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), cosmos_addr!("addr1"));

        let res = query::prover_for_chain(deps.as_ref(), chain_name!("chain2"));
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), cosmos_addr!("addr2"));
    }
}

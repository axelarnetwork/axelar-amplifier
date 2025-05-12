use axelar_wasm_std::{address, killswitch, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Reply, Response,
};
use error_stack::ResultExt;
use multisig::key::PublicKey;

mod execute;
mod query;
mod reply;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{
    Config, AVAILABLE_TICKETS, CONFIG, FEE_RESERVE, LAST_ASSIGNED_TICKET_NUMBER,
    NEXT_SEQUENCE_NUMBER,
};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
const BASE_VERSION: &str = "1.1.2";

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let config = Config {
        gateway: address::validate_cosmwasm_address(deps.api, &msg.gateway_address)?,
        multisig: address::validate_cosmwasm_address(deps.api, &msg.multisig_address)?,
        coordinator: address::validate_cosmwasm_address(deps.api, &msg.coordinator_address)?,
        service_registry: address::validate_cosmwasm_address(
            deps.api,
            &msg.service_registry_address,
        )?,
        voting_verifier: address::validate_cosmwasm_address(
            deps.api,
            &msg.voting_verifier_address,
        )?,
        signing_threshold: msg.signing_threshold,
        service_name: msg.service_name,
        chain_name: msg.chain_name,
        verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
        xrpl_multisig: msg.xrpl_multisig_address,
        xrpl_transaction_fee: msg.xrpl_transaction_fee,
        xrpl_base_reserve: msg.xrpl_base_reserve,
        xrpl_owner_reserve: msg.xrpl_owner_reserve,
        ticket_count_threshold: msg.ticket_count_threshold,
    };
    CONFIG.save(deps.storage, &config)?;

    permission_control::set_admin(deps.storage, &deps.api.addr_validate(&msg.admin_address)?)?;
    permission_control::set_governance(
        deps.storage,
        &deps.api.addr_validate(&msg.governance_address)?,
    )?;

    killswitch::init(deps.storage, killswitch::State::Disengaged)?;

    NEXT_SEQUENCE_NUMBER.save(deps.storage, &msg.next_sequence_number)?;
    LAST_ASSIGNED_TICKET_NUMBER.save(deps.storage, &msg.last_assigned_ticket_number)?;
    AVAILABLE_TICKETS.save(deps.storage, &msg.available_tickets)?;
    FEE_RESERVE.save(deps.storage, &msg.initial_fee_reserve)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    let config = CONFIG.load(deps.storage).expect("failed to load config");
    let gateway: xrpl_gateway::Client =
        client::ContractClient::new(deps.querier, &config.gateway).into();

    match msg.ensure_permissions(deps.storage, &info.sender)? {
        ExecuteMsg::TrustSet { token_id } => execute::construct_trust_set_proof(
            deps.storage,
            gateway,
            env.contract.address,
            &config,
            token_id,
        ),
        ExecuteMsg::ConstructProof { cc_id, payload } => execute::construct_payment_proof(
            deps.storage,
            deps.querier,
            gateway,
            env.contract.address,
            env.block.height,
            &config,
            cc_id,
            payload,
        ),
        ExecuteMsg::UpdateVerifierSet => {
            execute::update_verifier_set(deps.storage, deps.querier, env)
        }
        ExecuteMsg::ConfirmProverMessage { prover_message } => {
            execute::confirm_prover_message(deps.storage, deps.querier, &config, prover_message)
        }
        ExecuteMsg::TicketCreate => {
            execute::construct_ticket_create_proof(deps.storage, env.contract.address, &config)
        }
        ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        } => execute::update_signing_threshold(deps, new_signing_threshold),
        ExecuteMsg::UpdateXrplTransactionFee {
            new_transaction_fee,
        } => execute::update_xrpl_transaction_fee(deps, new_transaction_fee),
        ExecuteMsg::UpdateXrplReserves {
            new_base_reserve,
            new_owner_reserve,
        } => execute::update_xrpl_reserves(deps, new_base_reserve, new_owner_reserve),
        ExecuteMsg::UpdateAdmin { new_admin_address } => {
            execute::update_admin(deps, new_admin_address)
        }
        ExecuteMsg::ConfirmAddReservesMessage {
            add_reserves_message,
        } => execute::confirm_add_reserves_message(
            deps.storage,
            deps.querier,
            &config,
            add_reserves_message,
        ),
        ExecuteMsg::VerifySignature {
            session_id,
            message: _,
            public_key,
            signature,
            signer_address: _,
        } => execute::verify_signature(
            deps.storage,
            &session_id,
            &PublicKey::Ecdsa(public_key),
            &multisig::key::Signature::try_from((multisig::key::KeyType::Ecdsa, signature))
                .map_err(|_| ContractError::InvalidSignature)?,
        ),
        ExecuteMsg::DisableExecution => execute::disable_execution(deps),
        ExecuteMsg::EnableExecution => execute::enable_execution(deps),
    }?
    .then(Ok)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match reply.id {
        START_MULTISIG_REPLY_ID => reply::start_multisig_reply(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    let config = CONFIG.load(deps.storage)?;
    match msg {
        QueryMsg::Proof {
            multisig_session_id,
        } => to_json_binary(&query::proof(
            deps.storage,
            deps.querier,
            &config.multisig,
            multisig_session_id,
        )?),
        QueryMsg::VerifySignature {
            session_id,
            message: _,
            public_key,
            signature,
            signer_address: _,
        } => to_json_binary(&query::verify_signature(
            deps.storage,
            &session_id,
            &PublicKey::Ecdsa(public_key),
            &multisig::key::Signature::try_from((multisig::key::KeyType::Ecdsa, signature))
                .map_err(|_| ContractError::InvalidSignature)?,
        )?),
        QueryMsg::CurrentVerifierSet => to_json_binary(&query::current_verifier_set(deps.storage)?),
        QueryMsg::NextVerifierSet => to_json_binary(&query::next_verifier_set(deps.storage)?),
        QueryMsg::MultisigSession { cc_id } => {
            to_json_binary(&query::multisig_session(deps.storage, &cc_id)?)
        }
        QueryMsg::TicketCreate => to_json_binary(&query::ticket_create(
            deps.storage,
            config.ticket_count_threshold,
        )?),
        QueryMsg::IsEnabled => to_json_binary(&killswitch::is_contract_active(deps.storage)),
        QueryMsg::AvailableTickets => to_json_binary(&AVAILABLE_TICKETS.load(deps.storage)?),
        QueryMsg::NextSequenceNumber => to_json_binary(&NEXT_SEQUENCE_NUMBER.load(deps.storage)?),
        QueryMsg::FeeReserve => to_json_binary(&FEE_RESERVE.load(deps.storage)?),
    }
    .change_context(ContractError::SerializeResponse)
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    cw2::assert_contract_version(deps.storage, CONTRACT_NAME, BASE_VERSION)?;

    killswitch::init(deps.storage, killswitch::State::Disengaged)?;

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axelar_wasm_std::msg_id::HexTxHash;
    use axelar_wasm_std::permission_control::Permission;
    use axelar_wasm_std::{permission_control, MajorityThreshold, Threshold, VerificationStatus};
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{
        from_json, Addr, Empty, Fraction, HexBinary, OwnedDeps, SubMsgResponse, SubMsgResult,
        Uint128, Uint64,
    };
    use multisig::events::Event;
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use prost::Message;
    use router_api::ChainName;
    use xrpl_types::msg::XRPLProverMessage;
    use xrpl_types::types::{hash_signed_tx, XRPLAccountId};

    use super::*;
    use crate::axelar_verifiers::should_update_verifier_set;
    use crate::msg::{ProofResponse, ProofStatus};
    use crate::test::test_data::{self, TestOperator};
    use crate::test::test_utils::{
        mock_querier_handler, ADMIN, CHAIN_NAME, COORDINATOR_ADDRESS, GATEWAY_ADDRESS, GOVERNANCE,
        MULTISIG_ADDRESS, SERVICE_NAME, SERVICE_REGISTRY_ADDRESS, VOTING_VERIFIER_ADDRESS,
        XRPL_MULITISIG_ADDRESS,
    };

    const RELAYER: &str = "relayer";
    const MULTISIG_SESSION_ID: Uint64 = Uint64::one();

    pub fn setup_test_case() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let api = deps.api;

        deps.querier.update_wasm(mock_querier_handler(
            test_data::operators(),
            VerificationStatus::SucceededOnSourceChain,
        ));

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN), &[]),
            InstantiateMsg {
                admin_address: api.addr_make(ADMIN).to_string(),
                governance_address: api.addr_make(GOVERNANCE).to_string(),
                gateway_address: api.addr_make(GATEWAY_ADDRESS).to_string(),
                multisig_address: api.addr_make(MULTISIG_ADDRESS).to_string(),
                coordinator_address: api.addr_make(COORDINATOR_ADDRESS).to_string(),
                service_registry_address: api.addr_make(SERVICE_REGISTRY_ADDRESS).to_string(),
                voting_verifier_address: api.addr_make(VOTING_VERIFIER_ADDRESS).to_string(),
                signing_threshold: test_data::threshold(),
                service_name: SERVICE_NAME.to_string(),
                chain_name: CHAIN_NAME.parse().unwrap(),
                xrpl_multisig_address: XRPL_MULITISIG_ADDRESS.parse().unwrap(),
                verifier_set_diff_threshold: 0,
                xrpl_transaction_fee: 10,
                xrpl_base_reserve: 1000000,
                xrpl_owner_reserve: 200000,
                initial_fee_reserve: 60000000,
                ticket_count_threshold: 1,
                next_sequence_number: 44218446,
                last_assigned_ticket_number: 44218195,
                available_tickets: (44218195..44218200).collect::<Vec<_>>(),
            },
        )
        .unwrap();

        deps
    }

    fn execute_update_verifier_set(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::UpdateVerifierSet {};
        execute(
            deps,
            mock_env(),
            message_info(&MockApi::default().addr_make(ADMIN), &[]),
            msg,
        )
    }

    fn reply_update_verifier_set(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let session_id = to_json_binary(&MULTISIG_SESSION_ID).unwrap();
        let event = wasm_prefixed_event(Event::SigningStarted {
            session_id: MULTISIG_SESSION_ID,
            verifier_set_id: "".to_string(),
            pub_keys: HashMap::new(),
            msg: HexBinary::from([0u8; 32]).try_into().unwrap(),
            chain_name: "xrpl".parse().unwrap(),
            expires_at: 1000,
        });

        #[allow(deprecated)]
        // TODO: use `msg_responses` instead when the cosmwasm vm is updated to 2.x.x
        let response = SubMsgResponse {
            events: vec![event],
            // the reply data gets protobuf encoded when moving through the wasm module. We need to emulate this behaviour in tests as well
            data: Some(
                prost::bytes::Bytes::from(session_id.to_vec())
                    .encode_to_vec()
                    .into(),
            ),
            msg_responses: vec![],
        };

        reply(
            deps,
            mock_env(),
            Reply {
                id: START_MULTISIG_REPLY_ID,
                result: SubMsgResult::Ok(response),
                payload: vec![].into(),
                gas_used: 0,
            },
        )
    }

    fn confirm_prover_message(
        deps: DepsMut,
        prover_message: XRPLProverMessage,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::ConfirmProverMessage { prover_message };
        execute(
            deps,
            mock_env(),
            message_info(&MockApi::default().addr_make(RELAYER), &[]),
            msg,
        )
    }

    fn execute_update_signing_threshold(
        deps: DepsMut,
        sender: Addr,
        new_signing_threshold: MajorityThreshold,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        };
        execute(deps, mock_env(), message_info(&sender, &[]), msg)
    }

    fn execute_update_admin(
        deps: DepsMut,
        sender: Addr,
        new_admin_address: String,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::UpdateAdmin { new_admin_address };
        execute(deps, mock_env(), message_info(&sender, &[]), msg)
    }

    fn execute_construct_proof(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let outgoing_messages = test_data::outgoing_messages();
        let (message, payload) = outgoing_messages.first().unwrap();
        let msg = ExecuteMsg::ConstructProof {
            cc_id: message.cc_id.clone(),
            payload: payload.clone(),
        };
        execute(
            deps,
            mock_env(),
            message_info(&MockApi::default().addr_make(RELAYER), &[]),
            msg,
        )
    }

    fn wasm_prefixed_event(e: Event) -> cosmwasm_std::Event {
        let mut event: cosmwasm_std::Event = e.into();
        event.ty = format!("wasm-{}", event.ty);
        event
    }

    fn reply_construct_proof(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let session_id = to_json_binary(&MULTISIG_SESSION_ID).unwrap();
        let event = wasm_prefixed_event(Event::SigningStarted {
            session_id: MULTISIG_SESSION_ID,
            verifier_set_id: "".to_string(),
            pub_keys: HashMap::new(),
            msg: HexBinary::from([0u8; 32]).try_into().unwrap(),
            chain_name: "xrpl".parse().unwrap(),
            expires_at: 1000,
        });

        #[allow(deprecated)]
        // TODO: use `msg_responses` instead when the cosmwasm vm is updated to 2.x.x
        let response = SubMsgResponse {
            events: vec![event],
            // the reply data gets protobuf encoded when moving through the wasm module. We need to emulate this behaviour in tests as well
            data: Some(
                prost::bytes::Bytes::from(session_id.to_vec())
                    .encode_to_vec()
                    .into(),
            ),
            msg_responses: vec![],
        };

        reply(
            deps,
            mock_env(),
            Reply {
                id: START_MULTISIG_REPLY_ID,
                result: SubMsgResult::Ok(response),
                payload: vec![].into(),
                gas_used: 0,
            },
        )
    }

    fn query_proof(
        deps: Deps,
        multisig_session_id: Option<Uint64>,
    ) -> Result<ProofResponse, axelar_wasm_std::error::ContractError> {
        let multisig_session_id = match multisig_session_id {
            Some(id) => id,
            None => MULTISIG_SESSION_ID,
        };

        query(
            deps,
            mock_env(),
            QueryMsg::Proof {
                multisig_session_id,
            },
        )
        .map(|res| from_json(res).unwrap())
    }

    fn query_verifier_set(
        deps: Deps,
    ) -> Result<Option<multisig::verifier_set::VerifierSet>, axelar_wasm_std::error::ContractError>
    {
        query(deps, mock_env(), QueryMsg::CurrentVerifierSet {}).map(|res| from_json(res).unwrap())
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = setup_test_case();

        cw2::CONTRACT
            .save(
                deps.as_mut().storage,
                &cw2::ContractVersion {
                    contract: CONTRACT_NAME.to_string(),
                    version: BASE_VERSION.to_string(),
                },
            )
            .unwrap();

        migrate(deps.as_mut(), mock_env(), Empty {}).unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let api = MockApi::default();
        let instantiator = api.addr_make("instantiator");
        let admin = api.addr_make("admin");
        let governance = api.addr_make("governance");
        let gateway_address = api.addr_make("gateway_address");
        let multisig_address = api.addr_make("multisig_address");
        let coordinator_address = api.addr_make("coordinator_address");
        let service_registry_address = api.addr_make("service_registry_address");
        let voting_verifier_address = api.addr_make("voting_verifier");
        let signing_threshold = Threshold::try_from((
            test_data::threshold().numerator(),
            test_data::threshold().denominator(),
        ))
        .unwrap()
        .try_into()
        .unwrap();
        let service_name = "service_name";
        let chain_name: ChainName = "xrpl".parse().unwrap();
        let xrpl_multisig_address: XRPLAccountId =
            "rGAbJZEzU6WaYv5y1LfyN7LBBcQJ3TxsKC".parse().unwrap();

        let verifier_set_diff_threshold = 0u32;
        let xrpl_transaction_fee = 10u64;
        let xrpl_base_reserve = 1000000u64;
        let xrpl_owner_reserve = 200000u64;
        let initial_fee_reserve = 60000000u64;
        let ticket_count_threshold = 1u32;
        let next_sequence_number = 44218446u32;
        let last_assigned_ticket_number = 44218195u32;
        let available_tickets = (44218195..44218200).collect::<Vec<_>>();

        let mut deps = mock_dependencies();
        let info = message_info(&instantiator, &[]);
        let env = mock_env();

        let msg = InstantiateMsg {
            admin_address: admin.to_string(),
            governance_address: governance.to_string(),
            gateway_address: gateway_address.to_string(),
            multisig_address: multisig_address.to_string(),
            coordinator_address: coordinator_address.to_string(),
            voting_verifier_address: voting_verifier_address.to_string(),
            service_registry_address: service_registry_address.to_string(),
            signing_threshold,
            service_name: service_name.to_string(),
            chain_name,
            xrpl_multisig_address,
            verifier_set_diff_threshold,
            xrpl_transaction_fee,
            xrpl_base_reserve,
            xrpl_owner_reserve,
            initial_fee_reserve,
            ticket_count_threshold,
            next_sequence_number,
            last_assigned_ticket_number,
            available_tickets,
        };

        let res = instantiate(deps.as_mut(), env, info, msg);

        assert!(res.is_ok());
        let res = res.unwrap();

        assert_eq!(res.messages.len(), 0);

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.gateway, gateway_address);
        assert_eq!(config.multisig, multisig_address);
        assert_eq!(config.service_registry, service_registry_address);
        assert_eq!(config.signing_threshold, signing_threshold);
        assert_eq!(config.service_name, service_name);

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &admin).unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &governance).unwrap(),
            Permission::Governance.into()
        );
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn test_operators_to_verifier_set(operators: Vec<TestOperator>, nonce: u64) -> VerifierSet {
        let total_weight: Uint128 = operators
            .iter()
            .fold(Uint128::zero(), |acc, x| acc + x.weight);
        let quorum = total_weight.mul_ceil(test_data::threshold());
        VerifierSet {
            signers: operators
                .into_iter()
                .map(|op| {
                    (
                        op.address.clone().to_string(),
                        Signer {
                            address: op.address,
                            pub_key: op.pub_key,
                            weight: op.weight,
                        },
                    )
                })
                .collect(),
            threshold: quorum,
            created_at: nonce,
        }
    }

    #[test]
    fn test_update_verifier_set_fresh() {
        let mut deps = setup_test_case();
        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());
        assert!(verifier_set.unwrap().is_none());
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(test_data::operators(), mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set);
    }

    #[test]
    fn test_update_verifier_set_from_non_admin_or_governance_should_fail() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("some random address"), &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(
                permission_control::Error::PermissionDenied {
                    expected: Permission::Elevated.into(),
                    actual: Permission::NoPrivilege.into()
                }
            )
            .to_string()
        );
    }

    #[test]
    fn test_update_verifier_set_from_governance_should_succeed() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(GOVERNANCE), &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_update_verifier_set_from_admin_should_succeed() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(ADMIN), &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_update_verifier_set_remove_one() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();

        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::SucceededOnSourceChain,
        ));

        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(test_data::operators(), mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set);
    }

    #[test]
    fn test_update_verifier_set_add_one() {
        let mut deps = setup_test_case();

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();

        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set.clone(),
            VerificationStatus::SucceededOnSourceChain,
        ));

        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        deps.querier.update_wasm(mock_querier_handler(
            test_data::operators(),
            VerificationStatus::SucceededOnSourceChain,
        ));

        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(new_verifier_set, mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set);
    }

    #[test]
    fn test_update_verifier_set_change_public_key() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        let (a, b) = (
            new_verifier_set[0].pub_key.clone(),
            new_verifier_set[1].pub_key.clone(),
        );
        new_verifier_set[0].pub_key = b;
        new_verifier_set[1].pub_key = a;

        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::SucceededOnSourceChain,
        ));
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(test_data::operators(), mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set);
    }

    #[test]
    fn test_update_verifier_set_unchanged() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::VerifierSetUnchanged)
                .to_string()
        );
    }

    #[test]
    fn test_confirm_verifier_set_unconfirmed() {
        let mut deps = setup_test_case();

        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::Unknown,
        ));

        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());
        let res = reply_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let res = query_proof(deps.as_ref(), None).unwrap();
        let execute_data = match res.status {
            ProofStatus::Completed { execute_data } => execute_data,
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        };

        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(execute_data.as_slice()).unwrap(),
            unsigned_tx_hash: res.unsigned_tx_hash,
        };

        let res = confirm_prover_message(deps.as_mut(), prover_message);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::TxStatusUnknown).to_string()
        );
    }

    #[test]
    fn test_confirm_verifier_set_wrong_set() {
        let mut deps = setup_test_case();
        let res = execute_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let mut new_verifier_set = test_data::operators();
        new_verifier_set.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set.clone(),
            VerificationStatus::SucceededOnSourceChain,
        ));
        execute_update_verifier_set(deps.as_mut()).unwrap();
        let res = reply_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        new_verifier_set.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::Unknown,
        ));

        let res = query_proof(deps.as_ref(), None).unwrap();
        let execute_data = match res.status {
            ProofStatus::Completed { execute_data } => execute_data,
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        };

        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(execute_data.as_slice()).unwrap(),
            unsigned_tx_hash: res.unsigned_tx_hash,
        };

        let res = confirm_prover_message(deps.as_mut(), prover_message);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::TxStatusUnknown).to_string()
        );
    }

    #[test]
    fn confirm_prover_message_for_non_existent_proof_should_fail() {
        let mut deps = setup_test_case();

        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(&test_data::payment_proof()).unwrap(),
            unsigned_tx_hash: test_data::payment_unsigned_tx_hash(),
        };

        let res = confirm_prover_message(deps.as_mut(), prover_message);
        assert!(res.is_err());
        // assert_eq!(
        //     res.unwrap_err().to_string(),
        //     axelar_wasm_std::error::ContractError::from(ContractError::TxNotFound)
        //         .to_string()
        // );
    }

    #[test]
    fn test_construct_proof() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        execute_construct_proof(deps.as_mut()).unwrap();
        let res = reply_construct_proof(deps.as_mut()).unwrap();

        let event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");

        assert!(event.is_some());

        // test case where there is an existing payload
        execute_construct_proof(deps.as_mut()).unwrap();
        let res = reply_construct_proof(deps.as_mut()).unwrap(); // simulate reply from multisig
        let event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");

        assert!(event.is_some());
    }

    #[test]
    fn test_query_proof() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        execute_construct_proof(deps.as_mut()).unwrap();
        reply_construct_proof(deps.as_mut()).unwrap(); // simulate reply from multisig

        let res = query_proof(deps.as_ref(), None).unwrap();

        assert_eq!(res.unsigned_tx_hash, test_data::payment_unsigned_tx_hash());
        match res.status {
            ProofStatus::Completed { execute_data } => {
                assert_eq!(execute_data, test_data::payment_proof());
            }
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        }
    }

    #[test]
    fn test_construct_proof_no_verifier_set() {
        let mut deps = setup_test_case();
        let res = execute_construct_proof(deps.as_mut());
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::NoVerifierSet).to_string()
        );
    }

    #[test]
    fn non_governance_should_not_be_able_to_call_update_signing_threshold() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute_update_signing_threshold(
            deps.as_mut(),
            api.addr_make("random"),
            Threshold::try_from((6, 10)).unwrap().try_into().unwrap(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn governance_should_be_able_to_call_update_signing_threshold() {
        let mut deps = setup_test_case();
        let governance = deps.api.addr_make(GOVERNANCE);
        let res = execute_update_signing_threshold(
            deps.as_mut(),
            governance,
            Threshold::try_from((6, 10)).unwrap().try_into().unwrap(),
        );
        assert!(res.is_ok());
    }

    /// Calls update_signing_threshold, increasing the threshold by one.
    /// Returns (initial threshold, new threshold)
    fn update_signing_threshold_increase_by_one(deps: DepsMut) -> (Uint128, Uint128) {
        let verifier_set = query_verifier_set(deps.as_ref()).unwrap().unwrap();
        let initial_threshold = verifier_set.threshold;
        let total_weight = verifier_set
            .signers
            .iter()
            .fold(Uint128::zero(), |acc, signer| {
                acc.checked_add(signer.1.weight).unwrap()
            });
        let new_threshold = initial_threshold.checked_add(Uint128::one()).unwrap();

        let governance = MockApi::default().addr_make(GOVERNANCE);
        execute_update_signing_threshold(
            deps,
            governance.clone(),
            Threshold::try_from((
                Uint64::try_from(new_threshold).unwrap(),
                Uint64::try_from(total_weight).unwrap(),
            ))
            .unwrap()
            .try_into()
            .unwrap(),
        )
        .unwrap();
        (initial_threshold, new_threshold)
    }

    #[test]
    fn update_signing_threshold_should_not_change_current_threshold() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(deps.as_mut());
        assert_ne!(initial_threshold, new_threshold);

        let verifier_set = query_verifier_set(deps.as_ref()).unwrap().unwrap();
        assert_eq!(verifier_set.threshold, initial_threshold);
    }

    #[test]
    fn update_signing_threshold_should_change_future_threshold() {
        let mut deps = setup_test_case();

        execute_update_verifier_set(deps.as_mut()).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(deps.as_mut());
        assert_ne!(initial_threshold, new_threshold);

        execute_update_verifier_set(deps.as_mut()).unwrap();
        let res = reply_update_verifier_set(deps.as_mut()).unwrap();

        let proof_under_construction_event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");
        assert!(proof_under_construction_event.is_some());

        let unsigned_tx_hash: HexTxHash = from_json(
            proof_under_construction_event
                .as_ref()
                .unwrap()
                .attributes
                .iter()
                .find(|attr| attr.key == "unsigned_tx_hash")
                .unwrap()
                .value
                .clone(),
        )
        .unwrap();

        let signing_started_event = res
            .events
            .iter()
            .find(|event| event.ty == "xrpl_signing_started");
        assert!(signing_started_event.is_some());

        let res = query_proof(deps.as_ref(), None).unwrap();
        assert_eq!(res.unsigned_tx_hash, unsigned_tx_hash);
        let execute_data = match res.status {
            ProofStatus::Completed { execute_data } => {
                assert_eq!(execute_data, test_data::signer_list_set_proof());
                execute_data
            }
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        };

        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(execute_data.as_slice()).unwrap(),
            unsigned_tx_hash,
        };

        confirm_prover_message(deps.as_mut(), prover_message).unwrap();

        let verifier_set = query_verifier_set(deps.as_ref()).unwrap().unwrap();
        assert_eq!(verifier_set.threshold, new_threshold);
    }

    #[test]
    fn should_confirm_new_threshold() {
        let mut deps = setup_test_case();

        execute_update_verifier_set(deps.as_mut()).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(deps.as_mut());
        assert_ne!(initial_threshold, new_threshold);

        execute_update_verifier_set(deps.as_mut()).unwrap();
        let res = reply_update_verifier_set(deps.as_mut());
        assert!(res.is_ok());

        let res = query_proof(deps.as_ref(), None).unwrap();
        let execute_data = match res.status {
            ProofStatus::Completed { execute_data } => execute_data,
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        };

        let prover_message = XRPLProverMessage {
            tx_id: hash_signed_tx(execute_data.as_slice()).unwrap(),
            unsigned_tx_hash: res.unsigned_tx_hash,
        };

        let res = confirm_prover_message(deps.as_mut(), prover_message);
        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref()).unwrap().unwrap();
        assert_eq!(verifier_set.threshold, new_threshold);
    }

    #[test]
    fn should_update_verifier_set_no_change() {
        let verifier_set = test_data::new_verifier_set();
        assert!(!should_update_verifier_set(&verifier_set, &verifier_set, 0));
    }

    #[test]
    fn should_update_verifier_set_one_more() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            0
        ));
    }

    #[test]
    fn should_update_verifier_set_one_less() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(should_update_verifier_set(
            &new_verifier_set,
            &verifier_set,
            0
        ));
    }

    #[test]
    fn should_update_verifier_set_one_more_higher_threshold() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        new_verifier_set.signers.pop_first();
        assert!(!should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            1
        ));
    }

    #[test]
    fn should_update_verifier_set_diff_pub_key() {
        let verifier_set = test_data::new_verifier_set();
        let mut new_verifier_set = verifier_set.clone();
        let (first_key, first) = new_verifier_set.signers.pop_first().unwrap();
        let (last_key, last) = new_verifier_set.signers.pop_last().unwrap();
        new_verifier_set.signers.insert(
            last_key,
            Signer {
                pub_key: first.clone().pub_key,
                ..last.clone()
            },
        );
        new_verifier_set.signers.insert(
            first_key,
            Signer {
                pub_key: last.pub_key,
                ..first
            },
        );
        assert!(should_update_verifier_set(
            &verifier_set,
            &new_verifier_set,
            0
        ));
    }

    #[test]
    fn non_governance_should_not_be_able_to_call_update_admin() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let res = execute_update_admin(
            deps.as_mut(),
            api.addr_make("unauthorized"),
            "new admin".to_string(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn governance_should_be_able_to_call_update_admin() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let new_admin = api.addr_make("new admin");

        let res = execute_update_admin(
            deps.as_mut(),
            api.addr_make(GOVERNANCE),
            new_admin.to_string(),
        );
        assert!(res.is_ok(), "{:?}", res);

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &new_admin).unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &api.addr_make(ADMIN)).unwrap(),
            Permission::NoPrivilege.into()
        );
    }

    #[test]
    fn admin_should_be_able_to_call_update_admin() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let new_admin = api.addr_make("new admin");

        let res = execute_update_admin(deps.as_mut(), api.addr_make(ADMIN), new_admin.to_string());
        assert!(res.is_ok(), "{:?}", res);

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &new_admin).unwrap(),
            Permission::Admin.into()
        );

        assert_eq!(
            permission_control::sender_role(deps.as_ref().storage, &api.addr_make(ADMIN)).unwrap(),
            Permission::NoPrivilege.into()
        );
    }
}

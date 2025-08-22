use axelar_wasm_std::{address, permission_control};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response};
use error_stack::ResultExt;
use multisig_prover_api::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

use crate::error::ContractError;
use crate::state::{Config, CONFIG};

mod execute;
mod migrations;
mod query;
mod reply;

pub use migrations::{migrate, MigrateMsg};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

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
        chain_codec: address::validate_cosmwasm_address(deps.api, &msg.chain_codec_address)?,
        signing_threshold: msg.signing_threshold,
        service_name: msg.service_name,
        chain_name: msg.chain_name.parse()?,
        verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
        key_type: msg.key_type,
        sig_verifier_address: msg
            .sig_verifier_address
            .map(|addr| address::validate_cosmwasm_address(deps.api, &addr))
            .transpose()?,
    };
    CONFIG.save(deps.storage, &config)?;

    permission_control::set_admin(
        deps.storage,
        &address::validate_cosmwasm_address(deps.api, &msg.admin_address)?,
    )?;
    permission_control::set_governance(
        deps.storage,
        &address::validate_cosmwasm_address(deps.api, &msg.governance_address)?,
    )?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender)? {
        #[cfg(not(feature = "receive-payload"))]
        ExecuteMsg::ConstructProof(message_ids) => Ok(execute::construct_proof(deps, message_ids)?),
        #[cfg(feature = "receive-payload")]
        ExecuteMsg::ConstructProof {
            message_ids,
            full_message_payloads,
        } => Ok(execute::construct_proof(
            deps,
            message_ids,
            full_message_payloads,
        )?),
        ExecuteMsg::UpdateVerifierSet => Ok(execute::update_verifier_set(deps, env)?),
        ExecuteMsg::ConfirmVerifierSet => Ok(execute::confirm_verifier_set(deps, info.sender)?),
        ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        } => Ok(execute::update_signing_threshold(
            deps,
            new_signing_threshold,
        )?),
        ExecuteMsg::UpdateAdmin { new_admin_address } => {
            Ok(execute::update_admin(deps, new_admin_address)?)
        }
    }
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
    match msg {
        QueryMsg::Proof {
            multisig_session_id,
        } => to_json_binary(&query::proof(deps, multisig_session_id)?),
        QueryMsg::CurrentVerifierSet => to_json_binary(&query::current_verifier_set(deps)?),
        QueryMsg::NextVerifierSet => to_json_binary(&query::next_verifier_set(deps)?),
    }
    .change_context(ContractError::SerializeResponse)
    .map_err(axelar_wasm_std::error::ContractError::from)
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::permission_control::Permission;
    use axelar_wasm_std::{permission_control, MajorityThreshold, Threshold, VerificationStatus};
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{
        from_json, Addr, Empty, Fraction, HexBinary, OwnedDeps, SubMsgResponse, SubMsgResult,
        Uint128, Uint64,
    };
    use multisig::msg::Signer;
    use multisig::verifier_set::VerifierSet;
    use multisig_prover_api::msg::{ProofResponse, ProofStatus, VerifierSetResponse};
    use prost::Message;
    use router_api::{cosmos_addr, CrossChainId};

    use super::*;
    use crate::contract::execute::should_update_verifier_set;
    use crate::test::test_data::{self, TestOperator};
    use crate::test::test_utils::{
        mock_querier_handler, ADMIN, CHAIN_CODEC_ADDRESS, COORDINATOR_ADDRESS, GATEWAY_ADDRESS,
        GOVERNANCE, MULTISIG_ADDRESS, SERVICE_NAME, SERVICE_REGISTRY_ADDRESS,
        VOTING_VERIFIER_ADDRESS,
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
                chain_codec_address: api.addr_make(CHAIN_CODEC_ADDRESS).to_string(),
                signing_threshold: test_data::threshold(),
                service_name: SERVICE_NAME.to_string(),
                chain_name: "ganache-0".to_string(),
                verifier_set_diff_threshold: 0,
                key_type: multisig::key::KeyType::Ecdsa,
                sig_verifier_address: None,
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

    fn confirm_verifier_set(
        deps: DepsMut,
        sender: Addr,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let msg = ExecuteMsg::ConfirmVerifierSet {};
        execute(deps, mock_env(), message_info(&sender, &[]), msg)
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

    #[cfg(not(feature = "receive-payload"))]
    fn execute_construct_proof(
        deps: DepsMut,
        message_ids: Option<Vec<CrossChainId>>,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let message_ids = message_ids.unwrap_or_else(|| {
            test_data::messages()
                .into_iter()
                .map(|msg| msg.cc_id)
                .collect::<Vec<CrossChainId>>()
        });

        let msg = ExecuteMsg::ConstructProof(message_ids);
        execute(
            deps,
            mock_env(),
            message_info(&MockApi::default().addr_make(RELAYER), &[]),
            msg,
        )
    }

    fn reply_construct_proof(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::error::ContractError> {
        let session_id = to_json_binary(&MULTISIG_SESSION_ID).unwrap();

        #[allow(deprecated)]
        // TODO: use `msg_responses` instead when the cosmwasm vm is updated to 2.x.x
        let response = SubMsgResponse {
            events: vec![],
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
    ) -> Result<Option<VerifierSetResponse>, axelar_wasm_std::error::ContractError> {
        query(deps, mock_env(), QueryMsg::CurrentVerifierSet {}).map(|res| from_json(res).unwrap())
    }

    #[test]
    fn migrate_sets_contract_version() {
        let mut deps = setup_test_case();

        let chain_codec_address = deps.api.addr_make("chain_codec_address").to_string();

        migrate(
            deps.as_mut(),
            mock_env(),
            MigrateMsg {
                chain_codec_address,
            },
        )
        .unwrap();

        let contract_version = cw2::get_contract_version(deps.as_mut().storage).unwrap();
        assert_eq!(contract_version.contract, CONTRACT_NAME);
        assert_eq!(contract_version.version, CONTRACT_VERSION);
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let instantiator = cosmos_addr!("instantiator");
        let admin = cosmos_addr!("admin");
        let governance = cosmos_addr!("governance");
        let gateway_address = cosmos_addr!("gateway_address");
        let multisig_address = cosmos_addr!("multisig_address");
        let coordinator_address = cosmos_addr!("coordinator_address");
        let service_registry_address = cosmos_addr!("service_registry_address");
        let voting_verifier_address = cosmos_addr!("voting_verifier");
        let chain_codec_address = cosmos_addr!("chain_codec_address");
        let signing_threshold = Threshold::try_from((
            test_data::threshold().numerator(),
            test_data::threshold().denominator(),
        ))
        .unwrap()
        .try_into()
        .unwrap();
        let service_name = "service_name";

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
            chain_codec_address: chain_codec_address.to_string(),
            signing_threshold,
            service_name: service_name.to_string(),
            chain_name: "Ethereum".to_string(),
            verifier_set_diff_threshold: 0,
            key_type: multisig::key::KeyType::Ecdsa,
            sig_verifier_address: None,
        };

        let res = instantiate(deps.as_mut(), env, info, msg);

        assert!(res.is_ok());
        let res = res.unwrap();

        assert_eq!(res.messages.len(), 0);

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.gateway, gateway_address);
        assert_eq!(config.multisig, multisig_address);
        assert_eq!(config.service_registry, service_registry_address);
        assert_eq!(config.chain_codec, chain_codec_address);
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

        assert_eq!(verifier_set, expected_verifier_set.into());
    }

    #[test]
    fn test_update_verifier_set_from_non_admin_or_governance_should_fail() {
        let mut deps = setup_test_case();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("some random address"), &[]),
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

        assert_eq!(verifier_set, expected_verifier_set.into());
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

        assert_eq!(verifier_set, expected_verifier_set.into());
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

        assert_eq!(verifier_set, expected_verifier_set.into());
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

        let res = confirm_verifier_set(deps.as_mut(), cosmos_addr!("relayer"));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::VerifierSetNotConfirmed)
                .to_string()
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

        new_verifier_set.pop();
        deps.querier.update_wasm(mock_querier_handler(
            new_verifier_set,
            VerificationStatus::Unknown,
        ));

        let res = confirm_verifier_set(deps.as_mut(), cosmos_addr!("relayer"));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::VerifierSetNotConfirmed)
                .to_string()
        );
    }

    #[test]
    fn confirm_verifier_no_update_in_progress_should_fail() {
        let mut deps = setup_test_case();

        let res = confirm_verifier_set(deps.as_mut(), cosmos_addr!("relayer"));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::NoVerifierSetToConfirm)
                .to_string()
        );
    }

    #[test]
    #[cfg(not(feature = "receive-payload"))]
    fn test_construct_proof() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();

        execute_construct_proof(deps.as_mut(), None).unwrap();
        let res = reply_construct_proof(deps.as_mut()).unwrap();

        let event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");

        assert!(event.is_some());

        // test case where there is an existing payload
        execute_construct_proof(deps.as_mut(), None).unwrap();
        let res = reply_construct_proof(deps.as_mut()).unwrap(); // simulate reply from multisig
        let event = res
            .events
            .iter()
            .find(|event| event.ty == "proof_under_construction");

        assert!(event.is_some());
    }

    #[test]
    #[cfg(not(feature = "receive-payload"))]
    fn test_query_proof() {
        let mut deps = setup_test_case();
        execute_update_verifier_set(deps.as_mut()).unwrap();
        execute_construct_proof(deps.as_mut(), None).unwrap();
        reply_construct_proof(deps.as_mut()).unwrap(); // simulate reply from multisig

        let res = query_proof(deps.as_ref(), None).unwrap();

        assert_eq!(res.multisig_session_id, MULTISIG_SESSION_ID);
        assert_eq!(res.message_ids.len(), 1);
        match res.status {
            ProofStatus::Completed { execute_data } => {
                // the mock querier gives us mocked data:
                assert_eq!(
                    execute_data,
                    HexBinary::from_hex("48656c6c6f20776f726c6421").unwrap()
                );
            }
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        }
    }

    #[test]
    #[cfg(not(feature = "receive-payload"))]
    fn test_construct_proof_no_verifier_set() {
        let mut deps = setup_test_case();
        let res = execute_construct_proof(deps.as_mut(), None);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::NoVerifierSet).to_string()
        );
    }

    #[test]
    fn non_governance_should_not_be_able_to_call_update_signing_threshold() {
        let mut deps = setup_test_case();
        let res = execute_update_signing_threshold(
            deps.as_mut(),
            cosmos_addr!("random"),
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
        let verifier_set = query_verifier_set(deps.as_ref())
            .unwrap()
            .unwrap()
            .verifier_set;
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

        let verifier_set = query_verifier_set(deps.as_ref())
            .unwrap()
            .unwrap()
            .verifier_set;
        assert_eq!(verifier_set.threshold, initial_threshold);
    }

    #[test]
    fn update_signing_threshold_should_change_future_threshold() {
        let mut deps = setup_test_case();
        let api = deps.api;

        execute_update_verifier_set(deps.as_mut()).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(deps.as_mut());
        assert_ne!(initial_threshold, new_threshold);

        execute_update_verifier_set(deps.as_mut()).unwrap();

        let governance = api.addr_make(GOVERNANCE);
        confirm_verifier_set(deps.as_mut(), governance).unwrap();

        let verifier_set = query_verifier_set(deps.as_ref())
            .unwrap()
            .unwrap()
            .verifier_set;
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

        let res = confirm_verifier_set(deps.as_mut(), cosmos_addr!("relayer"));
        assert!(res.is_ok());

        let verifier_set = query_verifier_set(deps.as_ref())
            .unwrap()
            .unwrap()
            .verifier_set;
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
        let res = execute_update_admin(
            deps.as_mut(),
            cosmos_addr!("unauthorized"),
            "new admin".to_string(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn governance_should_be_able_to_call_update_admin() {
        let mut deps = setup_test_case();
        let api = deps.api;
        let new_admin = cosmos_addr!("new admin");

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
}

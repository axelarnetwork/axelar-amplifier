#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Reply, Response,
};
use error_stack::ResultExt;

use crate::{
    error::ContractError,
    execute, migrations,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    query, reply,
    state::{Config, CONFIG},
};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let config = make_config(&deps, msg)?;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::default())
}

fn make_config(
    deps: &DepsMut,
    msg: InstantiateMsg,
) -> Result<Config, axelar_wasm_std::ContractError> {
    let admin = deps.api.addr_validate(&msg.admin_address)?;
    let governance = deps.api.addr_validate(&msg.governance_address)?;
    let gateway = deps.api.addr_validate(&msg.gateway_address)?;
    let multisig = deps.api.addr_validate(&msg.multisig_address)?;
    let coordinator = deps.api.addr_validate(&msg.coordinator_address)?;
    let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;
    let voting_verifier = deps.api.addr_validate(&msg.voting_verifier_address)?;

    Ok(Config {
        admin,
        governance,
        gateway,
        multisig,
        coordinator,
        service_registry,
        voting_verifier,
        signing_threshold: msg.signing_threshold,
        service_name: msg.service_name,
        chain_name: msg
            .chain_name
            .parse()
            .map_err(|_| ContractError::InvalidChainName)?,
        verifier_set_diff_threshold: msg.verifier_set_diff_threshold,
        encoder: msg.encoder,
        key_type: msg.key_type,
        domain_separator: msg.domain_separator,
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match msg {
        ExecuteMsg::ConstructProof { message_ids } => execute::construct_proof(deps, message_ids),
        ExecuteMsg::UpdateVerifierSet {} => {
            execute::require_admin(&deps, info.clone())
                .or_else(|_| execute::require_governance(&deps, info))?;
            execute::update_verifier_set(deps, env)
        }
        ExecuteMsg::ConfirmVerifierSet {} => execute::confirm_verifier_set(deps, info.sender),
        ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        } => {
            execute::require_governance(&deps, info)?;
            execute::update_signing_threshold(deps, new_signing_threshold)
        }
        ExecuteMsg::UpdateAdmin { new_admin_address } => {
            execute::require_governance(&deps, info)?;
            execute::update_admin(deps, new_admin_address)
        }
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(
    deps: DepsMut,
    _env: Env,
    reply: Reply,
) -> Result<Response, axelar_wasm_std::ContractError> {
    match reply.id {
        START_MULTISIG_REPLY_ID => reply::start_multisig_reply(deps, reply),
        _ => unreachable!("unknown reply ID"),
    }
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    _env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::ContractError> {
    match msg {
        QueryMsg::GetProof {
            multisig_session_id,
        } => to_json_binary(&query::get_proof(deps, multisig_session_id)?),
        QueryMsg::GetVerifierSet {} => to_json_binary(&query::get_verifier_set(deps)?),
    }
    .change_context(ContractError::SerializeResponse)
    .map_err(axelar_wasm_std::ContractError::from)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response, axelar_wasm_std::ContractError> {
    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    migrations::v_0_5::migrate_verifier_sets(deps)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{
        from_json,
        testing::{mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage},
        Addr, Empty, Fraction, OwnedDeps, SubMsgResponse, SubMsgResult, Uint128, Uint64,
    };

    use axelar_wasm_std::{MajorityThreshold, Threshold, VerificationStatus};
    use multisig::{msg::Signer, verifier_set::VerifierSet};
    use prost::Message;
    use router_api::CrossChainId;

    use crate::{
        contract::execute::should_update_verifier_set,
        test::test_utils::{
            mock_querier_handler, ADMIN, COORDINATOR_ADDRESS, GATEWAY_ADDRESS, GOVERNANCE,
            MULTISIG_ADDRESS, SERVICE_NAME, SERVICE_REGISTRY_ADDRESS, VOTING_VERIFIER_ADDRESS,
        },
    };
    use crate::{
        encoding::Encoder,
        msg::{GetProofResponse, ProofStatus},
        test::test_data::{self, TestOperator},
    };

    use super::*;

    const RELAYER: &str = "relayer";
    const MULTISIG_SESSION_ID: Uint64 = Uint64::one();

    pub fn setup_test_case() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();

        deps.querier.update_wasm(mock_querier_handler(
            test_data::operators(),
            VerificationStatus::SucceededOnSourceChain,
        ));

        instantiate(
            deps.as_mut(),
            mock_env(),
            mock_info(ADMIN, &[]),
            InstantiateMsg {
                admin_address: ADMIN.to_string(),
                governance_address: GOVERNANCE.to_string(),
                gateway_address: GATEWAY_ADDRESS.to_string(),
                multisig_address: MULTISIG_ADDRESS.to_string(),
                coordinator_address: COORDINATOR_ADDRESS.to_string(),
                service_registry_address: SERVICE_REGISTRY_ADDRESS.to_string(),
                voting_verifier_address: VOTING_VERIFIER_ADDRESS.to_string(),
                signing_threshold: test_data::threshold(),
                service_name: SERVICE_NAME.to_string(),
                chain_name: "ganache-0".to_string(),
                verifier_set_diff_threshold: 0,
                encoder: crate::encoding::Encoder::Abi,
                key_type: multisig::key::KeyType::Ecdsa,
                domain_separator: [0; 32],
            },
        )
        .unwrap();

        deps
    }

    fn execute_update_verifier_set(
        deps: DepsMut,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let msg = ExecuteMsg::UpdateVerifierSet {};
        execute(deps, mock_env(), mock_info(ADMIN, &[]), msg)
    }

    fn confirm_verifier_set(
        deps: DepsMut,
        sender: Addr,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let msg = ExecuteMsg::ConfirmVerifierSet {};
        execute(deps, mock_env(), mock_info(sender.as_str(), &[]), msg)
    }

    fn execute_update_signing_threshold(
        deps: DepsMut,
        sender: Addr,
        new_signing_threshold: MajorityThreshold,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let msg = ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        };
        execute(deps, mock_env(), mock_info(sender.as_str(), &[]), msg)
    }

    fn execute_update_admin(
        deps: DepsMut,
        sender: &str,
        new_admin_address: String,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let msg = ExecuteMsg::UpdateAdmin { new_admin_address };
        execute(deps, mock_env(), mock_info(sender, &[]), msg)
    }

    fn execute_construct_proof(
        deps: DepsMut,
        message_ids: Option<Vec<CrossChainId>>,
    ) -> Result<Response, axelar_wasm_std::ContractError> {
        let message_ids = match message_ids {
            Some(ids) => ids,
            None => test_data::messages()
                .into_iter()
                .map(|msg| msg.cc_id)
                .collect::<Vec<CrossChainId>>(),
        };

        let msg = ExecuteMsg::ConstructProof { message_ids };
        execute(deps, mock_env(), mock_info(RELAYER, &[]), msg)
    }

    fn reply_construct_proof(deps: DepsMut) -> Result<Response, axelar_wasm_std::ContractError> {
        let session_id = to_json_binary(&MULTISIG_SESSION_ID).unwrap();

        let response = SubMsgResponse {
            events: vec![],
            // the reply data gets protobuf encoded when moving through the wasm module. We need to emulate this behaviour in tests as well
            data: Some(
                prost::bytes::Bytes::from(session_id.to_vec())
                    .encode_to_vec()
                    .into(),
            ),
        };

        reply(
            deps,
            mock_env(),
            Reply {
                id: START_MULTISIG_REPLY_ID,
                result: SubMsgResult::Ok(response),
            },
        )
    }

    fn query_get_proof(
        deps: Deps,
        multisig_session_id: Option<Uint64>,
    ) -> Result<GetProofResponse, axelar_wasm_std::ContractError> {
        let multisig_session_id = match multisig_session_id {
            Some(id) => id,
            None => MULTISIG_SESSION_ID,
        };

        query(
            deps,
            mock_env(),
            QueryMsg::GetProof {
                multisig_session_id,
            },
        )
        .map(|res| from_json(res).unwrap())
    }

    fn query_get_verifier_set(
        deps: Deps,
    ) -> Result<Option<VerifierSet>, axelar_wasm_std::ContractError> {
        query(deps, mock_env(), QueryMsg::GetVerifierSet {}).map(|res| from_json(res).unwrap())
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let instantiator = "instantiator";
        let admin = "admin";
        let governance = "governance";
        let gateway_address = "gateway_address";
        let multisig_address = "multisig_address";
        let coordinator_address = "coordinator_address";
        let service_registry_address = "service_registry_address";
        let voting_verifier_address = "voting_verifier";
        let signing_threshold = Threshold::try_from((
            test_data::threshold().numerator(),
            test_data::threshold().denominator(),
        ))
        .unwrap()
        .try_into()
        .unwrap();
        let service_name = "service_name";
        for encoding in [Encoder::Abi, Encoder::Bcs] {
            let mut deps = mock_dependencies();
            let info = mock_info(instantiator, &[]);
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
                chain_name: "Ethereum".to_string(),
                verifier_set_diff_threshold: 0,
                encoder: encoding,
                key_type: multisig::key::KeyType::Ecdsa,
                domain_separator: [0; 32],
            };

            let res = instantiate(deps.as_mut(), env, info, msg);

            assert!(res.is_ok());
            let res = res.unwrap();

            assert_eq!(res.messages.len(), 0);

            let config = CONFIG.load(deps.as_ref().storage).unwrap();
            assert_eq!(config.admin, admin);
            assert_eq!(config.gateway, gateway_address);
            assert_eq!(config.multisig, multisig_address);
            assert_eq!(config.service_registry, service_registry_address);
            assert_eq!(config.signing_threshold, signing_threshold);
            assert_eq!(config.service_name, service_name);
            assert_eq!(config.encoder, encoding)
        }
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
        let verifier_set = query_get_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());
        assert!(verifier_set.unwrap().is_none());
        let res = execute_update_verifier_set(deps.as_mut());

        assert!(res.is_ok());

        let verifier_set = query_get_verifier_set(deps.as_ref());
        assert!(verifier_set.is_ok());

        let verifier_set = verifier_set.unwrap().unwrap();

        let expected_verifier_set =
            test_operators_to_verifier_set(test_data::operators(), mock_env().block.height);

        assert_eq!(verifier_set, expected_verifier_set);
    }

    #[test]
    fn test_update_verifier_set_from_non_admin_or_governance_should_fail() {
        let mut deps = setup_test_case();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("some random address", &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
        );
    }

    #[test]
    fn test_update_verifier_set_from_governance_should_succeed() {
        let mut deps = setup_test_case();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(GOVERNANCE, &[]),
            ExecuteMsg::UpdateVerifierSet {},
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_update_verifier_set_from_admin_should_succeed() {
        let mut deps = setup_test_case();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(ADMIN, &[]),
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

        let verifier_set = query_get_verifier_set(deps.as_ref());
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

        let verifier_set = query_get_verifier_set(deps.as_ref());
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

        let verifier_set = query_get_verifier_set(deps.as_ref());
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
            axelar_wasm_std::ContractError::from(ContractError::VerifierSetUnchanged).to_string()
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

        let res = confirm_verifier_set(deps.as_mut(), Addr::unchecked("relayer"));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::VerifierSetNotConfirmed)
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

        let res = confirm_verifier_set(deps.as_mut(), Addr::unchecked("relayer"));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::VerifierSetNotConfirmed)
                .to_string()
        );
    }

    #[test]
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

        // test case where there is an existing batch
        execute_construct_proof(deps.as_mut(), None).unwrap();
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
        execute_construct_proof(deps.as_mut(), None).unwrap();
        reply_construct_proof(deps.as_mut()).unwrap(); // simulate reply from multisig

        let res = query_get_proof(deps.as_ref(), None).unwrap();

        assert_eq!(res.multisig_session_id, MULTISIG_SESSION_ID);
        assert_eq!(res.message_ids.len(), 1);
        match res.status {
            ProofStatus::Completed { execute_data } => {
                assert_eq!(execute_data, test_data::approve_messages_calldata());
            }
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        }
    }

    #[test]
    fn test_construct_proof_no_verifier_set() {
        let mut deps = setup_test_case();
        let res = execute_construct_proof(deps.as_mut(), None);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::ContractError::from(ContractError::NoVerifierSet).to_string()
        );
    }

    #[test]
    fn non_governance_should_not_be_able_to_call_update_signing_threshold() {
        let mut deps = setup_test_case();
        let res = execute_update_signing_threshold(
            deps.as_mut(),
            Addr::unchecked("random"),
            Threshold::try_from((6, 10)).unwrap().try_into().unwrap(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn governance_should_be_able_to_call_update_signing_threshold() {
        let mut deps = setup_test_case();
        let governance = Addr::unchecked(GOVERNANCE);
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
        let verifier_set = query_get_verifier_set(deps.as_ref()).unwrap().unwrap();
        let initial_threshold = verifier_set.threshold;
        let total_weight = verifier_set
            .signers
            .iter()
            .fold(Uint128::zero(), |acc, signer| {
                acc.checked_add(signer.1.weight).unwrap()
            });
        let new_threshold = initial_threshold.checked_add(Uint128::one()).unwrap();

        let governance = Addr::unchecked(GOVERNANCE);
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

        let verifier_set = query_get_verifier_set(deps.as_ref()).unwrap().unwrap();
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

        let governance = Addr::unchecked(GOVERNANCE);
        confirm_verifier_set(deps.as_mut(), governance).unwrap();

        let verifier_set = query_get_verifier_set(deps.as_ref()).unwrap().unwrap();
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

        let res = confirm_verifier_set(deps.as_mut(), Addr::unchecked("relayer"));
        assert!(res.is_ok());

        let verifier_set = query_get_verifier_set(deps.as_ref()).unwrap().unwrap();
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
        let res = execute_update_admin(deps.as_mut(), "unauthorized", "new admin".to_string());
        assert!(res.is_err());
    }

    #[test]
    fn governance_should_be_able_to_call_update_admin() {
        let mut deps = setup_test_case();
        let new_admin = "new admin";

        let res = execute_update_admin(deps.as_mut(), GOVERNANCE, new_admin.to_string());
        assert!(res.is_ok(), "{:?}", res);

        let config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config.admin, Addr::unchecked(new_admin));
    }
}

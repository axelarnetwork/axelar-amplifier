#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response, StdResult,
};

use crate::{
    error::ContractError,
    execute,
    msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg},
    query, reply,
    state::{Config, CONFIG},
};

pub const START_MULTISIG_REPLY_ID: u64 = 1;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
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
    let monitoring = deps.api.addr_validate(&msg.monitoring_address)?;
    let service_registry = deps.api.addr_validate(&msg.service_registry_address)?;
    let voting_verifier = deps.api.addr_validate(&msg.voting_verifier_address)?;

    Ok(Config {
        admin,
        governance,
        gateway,
        multisig,
        monitoring,
        service_registry,
        voting_verifier,
        destination_chain_id: msg.destination_chain_id,
        signing_threshold: msg.signing_threshold,
        service_name: msg.service_name,
        chain_name: msg
            .chain_name
            .parse()
            .map_err(|_| ContractError::InvalidChainName)?,
        worker_set_diff_threshold: msg.worker_set_diff_threshold,
        encoder: msg.encoder,
        key_type: msg.key_type,
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
        ExecuteMsg::UpdateWorkerSet {} => {
            execute::require_admin(&deps, info)?;
            execute::update_worker_set(deps, env)
        }
        ExecuteMsg::ConfirmWorkerSet {} => execute::confirm_worker_set(deps, info.sender),
        ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        } => {
            execute::require_governance(&deps, info)?;
            execute::update_signing_threshold(deps, new_signing_threshold)
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
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetProof {
            multisig_session_id,
        } => to_binary(&query::get_proof(deps, multisig_session_id)?),
        QueryMsg::GetWorkerSet {} => to_binary(&query::get_worker_set(deps)?),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::ContractError> {
    let old_config = CONFIG.load(deps.storage)?;
    let governance = deps.api.addr_validate(&msg.governance_address)?;
    let new_config = Config {
        governance,
        ..old_config
    };
    CONFIG.save(deps.storage, &new_config)?;

    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env, mock_info},
        Addr, Fraction, Uint128, Uint256, Uint64,
    };
    use cw_multi_test::{AppResponse, Executor};

    use axelar_wasm_std::{MajorityThreshold, Threshold};
    use connection_router_api::CrossChainId;
    use multisig::{msg::Signer, worker_set::WorkerSet};

    use crate::contract::execute::should_update_worker_set;
    use crate::{
        encoding::Encoder,
        msg::{GetProofResponse, ProofStatus},
        test::{
            mocks,
            multicontract::{setup_test_case, TestCaseConfig},
            test_data::{self, TestOperator},
        },
    };

    use super::*;

    const RELAYER: &str = "relayer";
    const MULTISIG_SESSION_ID: Uint64 = Uint64::one();

    fn execute_update_worker_set(test_case: &mut TestCaseConfig) -> Result<AppResponse, Error> {
        let msg = ExecuteMsg::UpdateWorkerSet {};
        test_case.app.execute_contract(
            test_case.admin.clone(),
            test_case.prover_address.clone(),
            &msg,
            &[],
        )
    }

    fn confirm_worker_set(
        test_case: &mut TestCaseConfig,
        sender: Addr,
    ) -> Result<AppResponse, Error> {
        let msg = ExecuteMsg::ConfirmWorkerSet {};
        test_case
            .app
            .execute_contract(sender, test_case.prover_address.clone(), &msg, &[])
    }

    fn execute_update_signing_threshold(
        test_case: &mut TestCaseConfig,
        sender: Addr,
        new_signing_threshold: MajorityThreshold,
    ) -> Result<AppResponse, Error> {
        let msg = ExecuteMsg::UpdateSigningThreshold {
            new_signing_threshold,
        };
        test_case
            .app
            .execute_contract(sender, test_case.prover_address.clone(), &msg, &[])
    }

    fn execute_construct_proof(
        test_case: &mut TestCaseConfig,
        message_ids: Option<Vec<CrossChainId>>,
    ) -> Result<AppResponse, Error> {
        let message_ids = match message_ids {
            Some(ids) => ids,
            None => test_data::messages()
                .into_iter()
                .map(|msg| msg.cc_id)
                .collect::<Vec<CrossChainId>>(),
        };

        let msg = ExecuteMsg::ConstructProof { message_ids };
        test_case.app.execute_contract(
            Addr::unchecked(RELAYER),
            test_case.prover_address.clone(),
            &msg,
            &[],
        )
    }

    fn query_get_proof(
        test_case: &mut TestCaseConfig,
        multisig_session_id: Option<Uint64>,
    ) -> StdResult<GetProofResponse> {
        let multisig_session_id = match multisig_session_id {
            Some(id) => id,
            None => MULTISIG_SESSION_ID,
        };

        test_case.app.wrap().query_wasm_smart(
            test_case.prover_address.clone(),
            &QueryMsg::GetProof {
                multisig_session_id,
            },
        )
    }

    fn query_get_worker_set(test_case: &mut TestCaseConfig) -> StdResult<WorkerSet> {
        test_case
            .app
            .wrap()
            .query_wasm_smart(test_case.prover_address.clone(), &QueryMsg::GetWorkerSet {})
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_instantiation() {
        let instantiator = "instantiator";
        let admin = "admin";
        let governance = "governance";
        let gateway_address = "gateway_address";
        let multisig_address = "multisig_address";
        let monitoring_address = "monitoring_address";
        let service_registry_address = "service_registry_address";
        let voting_verifier_address = "voting_verifier";
        let destination_chain_id = Uint256::one();
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
                monitoring_address: monitoring_address.to_string(),
                voting_verifier_address: voting_verifier_address.to_string(),
                service_registry_address: service_registry_address.to_string(),
                destination_chain_id,
                signing_threshold,
                service_name: service_name.to_string(),
                chain_name: "Ethereum".to_string(),
                worker_set_diff_threshold: 0,
                encoder: encoding,
                key_type: multisig::key::KeyType::Ecdsa,
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
            assert_eq!(config.destination_chain_id, destination_chain_id);
            assert_eq!(config.signing_threshold, signing_threshold);
            assert_eq!(config.service_name, service_name);
            assert_eq!(config.encoder, encoding)
        }
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn test_operators_to_worker_set(operators: Vec<TestOperator>, nonce: u64) -> WorkerSet {
        let total_weight: Uint256 = operators
            .iter()
            .fold(Uint256::zero(), |acc, x| acc + x.weight);
        let quorum = total_weight.mul_ceil(test_data::threshold());
        WorkerSet {
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
    fn test_update_worker_set_fresh() {
        let mut test_case = setup_test_case();
        let worker_set = query_get_worker_set(&mut test_case);
        assert!(worker_set.is_err());
        let res = execute_update_worker_set(&mut test_case);

        assert!(res.is_ok());

        let worker_set = query_get_worker_set(&mut test_case);
        assert!(worker_set.is_ok());

        let worker_set = worker_set.unwrap();

        let expected_worker_set =
            test_operators_to_worker_set(test_data::operators(), test_case.app.block_info().height);

        assert_eq!(worker_set, expected_worker_set);
    }

    #[test]
    fn test_update_worker_set_from_non_admin_should_fail() {
        let mut test_case = setup_test_case();
        let res = test_case.app.execute_contract(
            Addr::unchecked("some random address"),
            test_case.prover_address.clone(),
            &ExecuteMsg::UpdateWorkerSet {},
            &[],
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err()
                .downcast::<axelar_wasm_std::ContractError>()
                .unwrap()
                .to_string(),
            axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
        );
    }

    #[test]
    fn test_update_worker_set_remove_one() {
        let mut test_case = setup_test_case();
        let res = execute_update_worker_set(&mut test_case);

        assert!(res.is_ok());

        let mut new_worker_set = test_data::operators();
        new_worker_set.pop();
        mocks::service_registry::set_active_workers(
            &mut test_case.app,
            test_case.service_registry_address.clone(),
            new_worker_set,
        );
        let res = execute_update_worker_set(&mut test_case);

        assert!(res.is_ok());

        let worker_set = query_get_worker_set(&mut test_case);
        assert!(worker_set.is_ok());

        let worker_set = worker_set.unwrap();

        let expected_worker_set =
            test_operators_to_worker_set(test_data::operators(), test_case.app.block_info().height);

        assert_eq!(worker_set, expected_worker_set);
    }

    #[test]
    fn test_update_worker_set_add_one() {
        let mut test_case = setup_test_case();

        let mut new_worker_set = test_data::operators();
        new_worker_set.pop();

        mocks::service_registry::set_active_workers(
            &mut test_case.app,
            test_case.service_registry_address.clone(),
            new_worker_set.clone(),
        );

        let res = execute_update_worker_set(&mut test_case);
        assert!(res.is_ok());

        mocks::service_registry::set_active_workers(
            &mut test_case.app,
            test_case.service_registry_address.clone(),
            test_data::operators(),
        );

        let res = execute_update_worker_set(&mut test_case);
        assert!(res.is_ok());

        let worker_set = query_get_worker_set(&mut test_case);
        assert!(worker_set.is_ok());

        let worker_set = worker_set.unwrap();

        let expected_worker_set =
            test_operators_to_worker_set(new_worker_set, test_case.app.block_info().height);

        assert_eq!(worker_set, expected_worker_set);
    }

    #[test]
    fn test_update_worker_set_change_public_key() {
        let mut test_case = setup_test_case();
        let res = execute_update_worker_set(&mut test_case);

        assert!(res.is_ok());

        let mut new_worker_set = test_data::operators();
        let (a, b) = (
            new_worker_set[0].pub_key.clone(),
            new_worker_set[1].pub_key.clone(),
        );
        new_worker_set[0].pub_key = b;
        new_worker_set[1].pub_key = a;

        mocks::multisig::register_pub_keys(
            &mut test_case.app,
            test_case.multisig_address.clone(),
            new_worker_set,
        );
        let res = execute_update_worker_set(&mut test_case);

        assert!(res.is_ok());

        let worker_set = query_get_worker_set(&mut test_case);
        assert!(worker_set.is_ok());

        let worker_set = worker_set.unwrap();

        let expected_worker_set =
            test_operators_to_worker_set(test_data::operators(), test_case.app.block_info().height);

        assert_eq!(worker_set, expected_worker_set);
    }

    #[test]
    fn test_update_worker_set_unchanged() {
        let mut test_case = setup_test_case();
        let res = execute_update_worker_set(&mut test_case);

        assert!(res.is_ok());

        let res = execute_update_worker_set(&mut test_case);

        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err()
                .downcast::<axelar_wasm_std::ContractError>()
                .unwrap()
                .to_string(),
            axelar_wasm_std::ContractError::from(ContractError::WorkerSetUnchanged).to_string()
        );
    }

    #[test]
    fn test_confirm_worker_set_unconfirmed() {
        let mut test_case = setup_test_case();
        let res = execute_update_worker_set(&mut test_case);

        assert!(res.is_ok());

        let mut new_worker_set = test_data::operators();
        new_worker_set.pop();
        mocks::service_registry::set_active_workers(
            &mut test_case.app,
            test_case.service_registry_address.clone(),
            new_worker_set.clone(),
        );
        let res = execute_update_worker_set(&mut test_case);

        assert!(res.is_ok());

        let res = confirm_worker_set(&mut test_case, Addr::unchecked("relayer"));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err()
                .downcast::<axelar_wasm_std::ContractError>()
                .unwrap()
                .to_string(),
            axelar_wasm_std::ContractError::from(ContractError::WorkerSetNotConfirmed).to_string()
        );
    }

    #[test]
    fn test_confirm_worker_set_wrong_set() {
        let mut test_case = setup_test_case();
        let res = execute_update_worker_set(&mut test_case);

        assert!(res.is_ok());

        let mut new_worker_set = test_data::operators();
        new_worker_set.pop();
        mocks::service_registry::set_active_workers(
            &mut test_case.app,
            test_case.service_registry_address.clone(),
            new_worker_set.clone(),
        );
        let res = execute_update_worker_set(&mut test_case);

        new_worker_set.pop();
        let total_weight: Uint256 = new_worker_set
            .iter()
            .fold(Uint256::zero(), |acc, x| acc + x.weight);
        let quorum = total_weight.mul_ceil(test_data::threshold());
        mocks::voting_verifier::confirm_worker_set(
            &mut test_case.app,
            test_case.voting_verifier_address.clone(),
            new_worker_set,
            quorum,
        );

        assert!(res.is_ok());

        let res = confirm_worker_set(&mut test_case, Addr::unchecked("relayer"));
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err()
                .downcast::<axelar_wasm_std::ContractError>()
                .unwrap()
                .to_string(),
            axelar_wasm_std::ContractError::from(ContractError::WorkerSetNotConfirmed).to_string()
        );
    }

    #[test]
    fn test_construct_proof() {
        let mut test_case = setup_test_case();
        execute_update_worker_set(&mut test_case).unwrap();

        let res = execute_construct_proof(&mut test_case, None).unwrap();

        let event = res
            .events
            .iter()
            .find(|event| event.ty == "wasm-proof_under_construction");

        assert!(event.is_some());

        // test case where there is an existing batch
        let res = execute_construct_proof(&mut test_case, None).unwrap();
        let event = res
            .events
            .iter()
            .find(|event| event.ty == "wasm-proof_under_construction");

        assert!(event.is_some());
    }

    #[test]
    fn test_query_proof() {
        let mut test_case = setup_test_case();
        execute_update_worker_set(&mut test_case).unwrap();
        execute_construct_proof(&mut test_case, None).unwrap();

        let res = query_get_proof(&mut test_case, None).unwrap();

        assert_eq!(res.multisig_session_id, MULTISIG_SESSION_ID);
        assert_eq!(res.message_ids.len(), 1);
        match res.status {
            ProofStatus::Completed { execute_data } => {
                assert_eq!(execute_data, test_data::execute_data());
            }
            _ => panic!("Expected proof status to be completed"), // multisig mock will always return completed multisig
        }
    }

    #[test]
    fn test_construct_proof_no_worker_set() {
        let mut test_case = setup_test_case();
        let res = execute_construct_proof(&mut test_case, None);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err()
                .downcast::<axelar_wasm_std::ContractError>()
                .unwrap()
                .to_string(),
            axelar_wasm_std::ContractError::from(ContractError::NoWorkerSet).to_string()
        );
    }

    #[test]
    fn non_governance_should_not_be_able_to_call_update_signing_threshold() {
        let mut test_case = setup_test_case();
        let res = execute_update_signing_threshold(
            &mut test_case,
            Addr::unchecked("random"),
            Threshold::try_from((6, 10)).unwrap().try_into().unwrap(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn governance_should_be_able_to_call_update_signing_threshold() {
        let mut test_case = setup_test_case();
        let governance = test_case.governance.clone();
        let res = execute_update_signing_threshold(
            &mut test_case,
            governance,
            Threshold::try_from((6, 10)).unwrap().try_into().unwrap(),
        );
        assert!(res.is_ok());
    }

    /// Calls update_signing_threshold, increasing the threshold by one.
    /// Returns (initial threshold, new threshold)
    fn update_signing_threshold_increase_by_one(
        test_case: &mut TestCaseConfig,
    ) -> (Uint256, Uint256) {
        let worker_set = query_get_worker_set(test_case).unwrap();
        let initial_threshold = worker_set.threshold;
        let total_weight = worker_set
            .signers
            .iter()
            .fold(Uint256::zero(), |acc, signer| {
                acc.checked_add(signer.1.weight).unwrap()
            });
        let new_threshold = initial_threshold.checked_add(Uint256::one()).unwrap();

        let governance = test_case.governance.clone();
        execute_update_signing_threshold(
            test_case,
            governance.clone(),
            Threshold::try_from((
                Uint64::try_from(Uint128::try_from(new_threshold).unwrap()).unwrap(),
                Uint64::try_from(Uint128::try_from(total_weight).unwrap()).unwrap(),
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
        let mut test_case = setup_test_case();
        execute_update_worker_set(&mut test_case).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(&mut test_case);
        assert_ne!(initial_threshold, new_threshold);

        let worker_set = query_get_worker_set(&mut test_case).unwrap();
        assert_eq!(worker_set.threshold, initial_threshold);
    }

    #[test]
    fn update_signing_threshold_should_change_future_threshold() {
        let mut test_case = setup_test_case();
        execute_update_worker_set(&mut test_case).unwrap();

        let (initial_threshold, new_threshold) =
            update_signing_threshold_increase_by_one(&mut test_case);
        assert_ne!(initial_threshold, new_threshold);

        execute_update_worker_set(&mut test_case).unwrap();

        let governance = test_case.governance.clone();
        confirm_worker_set(&mut test_case, governance).unwrap();

        let worker_set = query_get_worker_set(&mut test_case).unwrap();
        assert_eq!(worker_set.threshold, new_threshold);
    }

    // #[test]
    // fn should_confirm_new_threshold_via_voting_verifier() {
    //     let mut test_case = setup_test_case();
    //     execute_update_worker_set(&mut test_case).unwrap();
    //
    //     let (initial_threshold, new_threshold) =
    //         update_signing_threshold_increase_by_one(&mut test_case);
    //     assert_ne!(initial_threshold, new_threshold);
    //
    //     execute_update_worker_set(&mut test_case).unwrap();
    //
    //     mocks::voting_verifier::confirm_worker_set(
    //         &mut test_case.app,
    //         test_case.voting_verifier_address.clone(),
    //         test_data::operators(),
    //         new_threshold,
    //     );
    //     let res = confirm_worker_set(&mut test_case, Addr::unchecked("relayer"));
    //     assert!(res.is_ok());
    //
    //     let worker_set = query_get_worker_set(&mut test_case).unwrap();
    //     assert_eq!(worker_set.threshold, new_threshold);
    // }

    #[test]
    fn should_update_worker_set_no_change() {
        let worker_set = test_data::new_worker_set();
        assert!(!should_update_worker_set(&worker_set, &worker_set, 0));
    }

    #[test]
    fn should_update_worker_set_one_more() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        new_worker_set.signers.pop_first();
        assert!(should_update_worker_set(&worker_set, &new_worker_set, 0));
    }

    #[test]
    fn should_update_worker_set_one_less() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        new_worker_set.signers.pop_first();
        assert!(should_update_worker_set(&new_worker_set, &worker_set, 0));
    }

    #[test]
    fn should_update_worker_set_one_more_higher_threshold() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        new_worker_set.signers.pop_first();
        assert!(!should_update_worker_set(&worker_set, &new_worker_set, 1));
    }

    #[test]
    fn should_update_worker_set_diff_pub_key() {
        let worker_set = test_data::new_worker_set();
        let mut new_worker_set = worker_set.clone();
        let (first_key, first) = new_worker_set.signers.pop_first().unwrap();
        let (last_key, last) = new_worker_set.signers.pop_last().unwrap();
        new_worker_set.signers.insert(
            last_key,
            Signer {
                pub_key: first.clone().pub_key,
                ..last.clone()
            },
        );
        new_worker_set.signers.insert(
            first_key,
            Signer {
                pub_key: last.pub_key,
                ..first
            },
        );
        assert!(should_update_worker_set(&worker_set, &new_worker_set, 0));
    }
}

use axelar_wasm_std::{address, permission_control, FnExt};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, BankMsg, Binary, Coin, Deps, DepsMut, Env, MessageInfo, Response, Storage,
};
use error_stack::{bail, Report, ResultExt};
use service_registry_api::error::ContractError;
use service_registry_api::{AuthorizationState, BondingState, Service};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{self, VERIFIERS};

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

    let governance = address::validate_cosmwasm_address(deps.api, &msg.governance_account)?;
    permission_control::set_governance(deps.storage, &governance)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    match msg.ensure_permissions(deps.storage, &info.sender, match_verifier(&info.sender))? {
        ExecuteMsg::RegisterService {
            service_name,
            coordinator_contract,
            min_num_verifiers,
            max_num_verifiers,
            min_verifier_bond,
            bond_denom,
            unbonding_period_days,
            description,
        } => {
            let coordinator_contract = deps.api.addr_validate(&coordinator_contract)?;
            execute::register_service(
                deps,
                service_name,
                coordinator_contract,
                min_num_verifiers,
                max_num_verifiers,
                min_verifier_bond,
                bond_denom,
                unbonding_period_days,
                description,
            )
        }
        ExecuteMsg::UpdateService {
            service_name,
            updated_service_params,
        } => execute::update_service(deps, service_name, updated_service_params.into()),
        ExecuteMsg::OverrideServiceParams {
            service_name,
            chain_name,
            service_params_override,
        } => execute::override_service_params(
            deps,
            service_name,
            chain_name,
            service_params_override.into(),
        ),
        ExecuteMsg::RemoveServiceParamsOverride {
            service_name,
            chain_name,
        } => execute::remove_service_params_override(deps, service_name, chain_name),
        ExecuteMsg::AuthorizeVerifiers {
            verifiers,
            service_name,
        } => {
            let verifiers = verifiers
                .into_iter()
                .map(|verifier| address::validate_cosmwasm_address(deps.api, &verifier))
                .collect::<Result<Vec<_>, _>>()?;
            execute::update_verifier_authorization_status(
                deps,
                verifiers,
                service_name,
                AuthorizationState::Authorized,
            )
        }
        ExecuteMsg::UnauthorizeVerifiers {
            verifiers,
            service_name,
        } => {
            let verifiers = verifiers
                .into_iter()
                .map(|verifier| address::validate_cosmwasm_address(deps.api, &verifier))
                .collect::<Result<Vec<_>, _>>()?;
            execute::update_verifier_authorization_status(
                deps,
                verifiers,
                service_name,
                AuthorizationState::NotAuthorized,
            )
        }
        ExecuteMsg::JailVerifiers {
            verifiers,
            service_name,
        } => {
            let verifiers = verifiers
                .into_iter()
                .map(|verifier| address::validate_cosmwasm_address(deps.api, &verifier))
                .collect::<Result<Vec<_>, _>>()?;
            execute::update_verifier_authorization_status(
                deps,
                verifiers,
                service_name,
                AuthorizationState::Jailed,
            )
        }
        ExecuteMsg::RegisterChainSupport {
            service_name,
            chains,
        } => execute::register_chains_support(deps, info, service_name, chains),
        ExecuteMsg::DeregisterChainSupport {
            service_name,
            chains,
        } => execute::deregister_chains_support(deps, info, service_name, chains),
        ExecuteMsg::BondVerifier { service_name } => {
            execute::bond_verifier(deps, info, service_name)
        }
        ExecuteMsg::UnbondVerifier { service_name } => {
            execute::unbond_verifier(deps, env, info, service_name)
        }
        ExecuteMsg::ClaimStake { service_name } => {
            execute::claim_stake(deps, env, info, service_name)
        }
    }?
    .then(Ok)
}

fn match_verifier(
    sender: &Addr,
) -> impl FnOnce(&dyn Storage, &ExecuteMsg) -> Result<Addr, Report<permission_control::Error>> + '_
{
    |storage: &dyn Storage, msg: &ExecuteMsg| {
        let service_name = match msg {
            ExecuteMsg::RegisterChainSupport { service_name, .. }
            | ExecuteMsg::DeregisterChainSupport { service_name, .. } => service_name,
            _ => bail!(permission_control::Error::WrongVariant),
        };
        let res = VERIFIERS
            .load(storage, (service_name, sender))
            .map(|verifier| verifier.address)
            .change_context(ContractError::VerifierNotFound)
            .change_context(permission_control::Error::Unauthorized);

        // on error, check if the service even exists, and if it doesn't, return ServiceNotFound
        if res.is_err() {
            state::service(storage, service_name, None)
                .change_context(permission_control::Error::Unauthorized)?;
        }
        res
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(
    deps: Deps,
    env: Env,
    msg: QueryMsg,
) -> Result<Binary, axelar_wasm_std::error::ContractError> {
    match msg {
        QueryMsg::ActiveVerifiers {
            service_name,
            chain_name,
        } => to_json_binary(&query::active_verifiers(
            deps,
            env,
            service_name,
            chain_name,
        )?)
        .map_err(|err| err.into()),
        QueryMsg::Verifier {
            service_name,
            verifier,
        } => to_json_binary(&query::verifier(deps, service_name, verifier)?)
            .map_err(|err| err.into()),
        QueryMsg::Service {
            service_name,
            chain_name,
        } => to_json_binary(&query::service(deps, service_name, chain_name)?)
            .map_err(|err| err.into()),
        QueryMsg::ServiceParamsOverride {
            service_name,
            chain_name,
        } => to_json_binary(&query::service_params_override(
            deps,
            service_name,
            chain_name,
        )?)
        .map_err(|err| err.into()),
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use axelar_wasm_std::error::err_contains;
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::testing::{
        message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{
        coins, from_json, Api, CosmosMsg, Empty, OwnedDeps, StdResult, Uint128, WasmQuery,
    };
    use router_api::{chain_name, cosmos_addr, ChainName};
    use service_registry_api::{Verifier, WeightedVerifier};

    use super::*;
    use crate::msg::{ServiceParamsOverride, UpdatedServiceParams, VerifierDetails};
    use crate::state::VERIFIER_WEIGHT;

    const AXL_DENOMINATION: &str = "uaxl";

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();

        instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("instantiator"), &[]),
            InstantiateMsg {
                governance_account: cosmos_addr!("governance").to_string(),
            },
        )
        .unwrap();

        let coordinator_address = cosmos_addr!("coordinator");
        deps.querier.update_wasm(move |wq| match wq {
            WasmQuery::Smart { contract_addr, .. }
                if contract_addr == coordinator_address.as_str() =>
            {
                Ok(to_json_binary(&true).into()).into()
            }
            _ => panic!("no mock for this query"),
        });

        deps
    }

    fn assert_auth_verifier_count_is_valid(
        deps: &OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
        service_name: &String,
        expected: u16,
    ) {
        let stored_count =
            crate::state::number_of_authorized_verifiers(&deps.storage, &service_name.to_string())
                .expect("Failed to get authorized verifier count");

        let actual_count = crate::state::VERIFIERS
            .prefix(&service_name.to_string())
            .range(&deps.storage, None, None, cosmwasm_std::Order::Ascending)
            .filter_map(|item| item.ok().map(|(_, verifier)| verifier))
            .filter(|verifier| verifier.authorization_state == AuthorizationState::Authorized)
            .count();

        let actual_count = u16::try_from(actual_count).expect("actual count should fit in u16");

        assert_eq!(
            stored_count, expected,
            "authorized verifier counter doesn't match expected"
        );
        assert_eq!(
            actual_count, expected,
            "actual authorized verifier count doesn't match expected"
        );
    }

    fn execute_register_service(deps: DepsMut, service_name: String) -> Service {
        let service = Service {
            name: service_name,
            coordinator_contract: cosmos_addr!("coordinator"),
            min_num_verifiers: 0,
            max_num_verifiers: Some(100),
            min_verifier_bond: Uint128::one().try_into().unwrap(),
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "amplifier service".into(),
        };
        let res = execute(
            deps,
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service.name.clone(),
                coordinator_contract: service.coordinator_contract.to_string(),
                min_num_verifiers: service.min_num_verifiers,
                max_num_verifiers: service.max_num_verifiers,
                min_verifier_bond: service.min_verifier_bond,
                bond_denom: service.bond_denom.clone(),
                unbonding_period_days: service.unbonding_period_days,
                description: service.description.clone(),
            },
        );
        assert!(res.is_ok());
        service
    }

    fn execute_override_service_params(
        deps: DepsMut,
        service_name: String,
        chain_name: ChainName,
    ) -> ServiceParamsOverride {
        let min_verifiers_override = 20;
        let max_verifiers_override = Some(20);

        let service_params_override = ServiceParamsOverride {
            min_num_verifiers: Some(min_verifiers_override),
            max_num_verifiers: Some(max_verifiers_override),
        };

        let res = execute(
            deps,
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::OverrideServiceParams {
                service_name,
                chain_name: chain_name.clone(),
                service_params_override: service_params_override.clone(),
            },
        );

        assert!(res.is_ok());
        service_params_override
    }

    fn setup_service_with_5_verifiers() -> (
        OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
        MockApi,
        String,
        Vec<String>,
    ) {
        let mut deps = setup();
        let api = deps.api;
        let service_name = "validators";

        let response = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(10),
                min_verifier_bond: Uint128::new(100).try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(response.is_ok());

        let verifiers = vec![
            cosmos_addr!("verifier1").to_string(),
            cosmos_addr!("verifier2").to_string(),
            cosmos_addr!("verifier3").to_string(),
            cosmos_addr!("verifier4").to_string(),
            cosmos_addr!("verifier5").to_string(),
        ];

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: verifiers.clone(),
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        assert_auth_verifier_count_is_valid(&deps, &service_name.to_string(), 5);

        (deps, api, service_name.into(), verifiers)
    }

    #[test]
    fn register_service() {
        let mut deps = setup();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: "validators".into(),
                coordinator_contract: cosmos_addr!("nowhere").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: Uint128::one().try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("unauthorized"), &[]),
            ExecuteMsg::RegisterService {
                service_name: "validators".into(),
                coordinator_contract: cosmos_addr!("nowhere").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: Uint128::one().try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        )
        .unwrap_err();
        assert!(err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::PermissionDenied { .. }
        ));
    }

    #[test]
    fn update_service_should_update_all_values() {
        let mut deps = setup();

        let service_name = "validators";

        let service = execute_register_service(deps.as_mut(), service_name.into());

        // update all configurable values
        let updated_params = UpdatedServiceParams {
            min_num_verifiers: Some(service.min_num_verifiers + 1),
            max_num_verifiers: Some(service.max_num_verifiers.map(|max| max + 1)),
            min_verifier_bond: Some(
                service
                    .min_verifier_bond
                    .into_inner()
                    .strict_add(Uint128::one())
                    .try_into()
                    .unwrap(),
            ),
            unbonding_period_days: Some(service.unbonding_period_days + 1),
        };

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::UpdateService {
                service_name: service_name.into(),
                updated_service_params: updated_params.clone(),
            },
        );
        assert!(res.is_ok());

        let res: Service = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Service {
                    service_name: service.name.clone(),
                    chain_name: None,
                },
            )
            .unwrap(),
        )
        .unwrap();

        let expected_service = Service {
            max_num_verifiers: updated_params.max_num_verifiers.unwrap(),
            min_num_verifiers: updated_params.min_num_verifiers.unwrap(),
            min_verifier_bond: updated_params.min_verifier_bond.unwrap(),
            unbonding_period_days: updated_params.unbonding_period_days.unwrap(),
            ..service
        };
        assert_eq!(res, expected_service);
    }

    #[test]
    fn update_service_should_update_only_specified_values() {
        let mut deps = setup();

        let service_name = "verifiers";

        let service = execute_register_service(deps.as_mut(), service_name.into());

        // check None values are ignored
        let new_min_bond = service
            .min_verifier_bond
            .into_inner()
            .strict_add(Uint128::one())
            .try_into()
            .unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::UpdateService {
                service_name: service_name.into(),
                updated_service_params: UpdatedServiceParams {
                    min_num_verifiers: None,
                    max_num_verifiers: None,
                    min_verifier_bond: Some(new_min_bond),
                    unbonding_period_days: None,
                },
            },
        );
        assert!(res.is_ok());

        let res: Service = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Service {
                    service_name: service_name.into(),
                    chain_name: None,
                },
            )
            .unwrap(),
        )
        .unwrap();

        let expected_service = Service {
            min_verifier_bond: new_min_bond,
            ..service
        };
        assert_eq!(res, expected_service);
    }

    #[test]
    fn update_service_should_only_be_callable_by_governance() {
        let mut deps = setup();

        let service_name = "validators";

        let service = execute_register_service(deps.as_mut(), service_name.into());
        // check permissions are handled correctly
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("unauthorized"), &[]),
            ExecuteMsg::UpdateService {
                service_name: service.name,
                updated_service_params: UpdatedServiceParams {
                    min_num_verifiers: Some(10),
                    max_num_verifiers: None,
                    min_verifier_bond: None,
                    unbonding_period_days: None,
                },
            },
        );

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::PermissionDenied { .. }
        ));
    }

    #[test]
    fn override_service_params_should_succeed() {
        let mut deps = setup();

        let service_name = "verifiers";
        let chain_name = chain_name!("solana");
        let min_verifiers_override = 20;
        let max_verifiers_override = Some(20);

        let service_params_override = ServiceParamsOverride {
            min_num_verifiers: Some(min_verifiers_override),
            max_num_verifiers: Some(max_verifiers_override),
        };

        let service = execute_register_service(deps.as_mut(), service_name.into());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::OverrideServiceParams {
                service_name: service_name.into(),
                chain_name: chain_name.clone(),
                service_params_override,
            },
        );
        assert!(res.is_ok());

        let res: Service = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Service {
                    service_name: service_name.into(),
                    chain_name: Some(chain_name),
                },
            )
            .unwrap(),
        )
        .unwrap();

        let expected_service = Service {
            min_num_verifiers: min_verifiers_override,
            max_num_verifiers: max_verifiers_override,
            ..service
        };

        assert_eq!(res, expected_service);
    }

    #[test]
    fn override_service_params_should_fail_when_service_does_not_exist() {
        let mut deps = setup();

        let service_name = "verifiers";
        let chain_name = chain_name!("solana");
        let min_verifiers_override = 20;
        let max_verifiers_override = Some(20);

        let service_params_override = ServiceParamsOverride {
            min_num_verifiers: Some(min_verifiers_override),
            max_num_verifiers: Some(max_verifiers_override),
        };

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::OverrideServiceParams {
                service_name: service_name.into(),
                chain_name,
                service_params_override,
            },
        );

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::ServiceNotFound
        ));
    }

    #[test]
    fn override_service_params_should_only_be_callable_by_governance() {
        let mut deps = setup();

        let service_name = "verifiers";
        let chain_name = chain_name!("solana");
        let min_verifiers_override = 20;
        let max_verifiers_override = Some(20);

        let service_params_override = ServiceParamsOverride {
            min_num_verifiers: Some(min_verifiers_override),
            max_num_verifiers: Some(max_verifiers_override),
        };

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("unauthorized"), &[]),
            ExecuteMsg::OverrideServiceParams {
                service_name: service_name.into(),
                chain_name,
                service_params_override,
            },
        );

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::PermissionDenied { .. }
        ));
    }

    #[test]
    fn remove_service_params_override_should_remove_override() {
        let mut deps = setup();

        let service_name = "verifiers";
        let chain_name = chain_name!("solana");

        let service = execute_register_service(deps.as_mut(), service_name.into());
        execute_override_service_params(deps.as_mut(), service_name.into(), chain_name.clone());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RemoveServiceParamsOverride {
                service_name: service_name.into(),
                chain_name: chain_name.clone(),
            },
        );

        assert!(res.is_ok());

        let res: Service = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Service {
                    service_name: service_name.into(),
                    chain_name: Some(chain_name),
                },
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(res, service);
    }

    #[test]
    fn remove_service_params_override_should_fail_when_it_does_not_exist() {
        let mut deps = setup();

        let service_name = "verifiers";
        let chain_name = chain_name!("solana");

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RemoveServiceParamsOverride {
                service_name: service_name.into(),
                chain_name: chain_name.clone(),
            },
        );

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::ServiceOverrideNotFound
        ));
    }

    #[test]
    fn remove_service_params_override_should_only_be_callable_by_governance() {
        let mut deps = setup();

        let service_name = "verifiers";
        let chain_name = chain_name!("solana");

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("unauthorized"), &[]),
            ExecuteMsg::RemoveServiceParamsOverride {
                service_name: service_name.into(),
                chain_name,
            },
        );

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::PermissionDenied { .. }
        ));
    }

    #[test]
    fn query_service_params_override_succeeds() {
        let mut deps = setup();

        let service_name = "verifiers";
        let chain_name = chain_name!("solana");

        execute_register_service(deps.as_mut(), service_name.into());
        let params_override =
            execute_override_service_params(deps.as_mut(), service_name.into(), chain_name.clone());

        let res: Option<ServiceParamsOverride> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ServiceParamsOverride {
                    service_name: service_name.into(),
                    chain_name: chain_name.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(res, Some(params_override));
    }

    #[test]
    fn query_service_params_override_returns_none_if_does_not_exist() {
        let deps = setup();

        let service_name = "verifiers";
        let chain_name = chain_name!("solana");

        let res: Option<ServiceParamsOverride> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ServiceParamsOverride {
                    service_name: service_name.into(),
                    chain_name: chain_name.clone(),
                },
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(res, None);
    }

    #[test]
    fn authorize_verifier() {
        let mut deps = setup();

        let service_name = "validators";
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("nowhere").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: Uint128::one().try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("unauthorized"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").into()],
                service_name: service_name.into(),
            },
        )
        .unwrap_err();
        assert!(err_contains!(
            err.report,
            permission_control::Error,
            permission_control::Error::PermissionDenied { .. }
        ));
    }

    #[test]
    fn bond_verifier() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("nowhere").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());
    }

    #[test]
    fn bond_verifier_zero_bond_should_fail() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("nowhere").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn register_chain_support() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("nowhere").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifiers,
            vec![WeightedVerifier {
                verifier_info: Verifier {
                    address: cosmos_addr!("verifier"),
                    bonding_state: BondingState::Bonded {
                        amount: min_verifier_bond.try_into().unwrap(),
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: VERIFIER_WEIGHT
            }]
        );

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name: chain_name!("random chain"),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![]);
    }

    /// If a bonded and authorized verifier deregisters support for a chain they previously registered support for,
    /// that verifier should no longer be part of the active verifier set for that chain
    #[test]
    fn register_and_deregister_support_for_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("nowhere").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        // Deregister chain support
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![]);
    }

    /// Same setting and goal as register_and_deregister_support_for_single_chain() but for multiple chains.
    #[test]
    fn register_and_deregister_support_for_multiple_chains() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chains = vec![
            chain_name!("ethereum"),
            chain_name!("binance"),
            chain_name!("avalanche"),
        ];

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: chains.clone(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: chains.clone(),
            },
        );
        assert!(res.is_ok());

        for chain in chains {
            let verifiers: Vec<WeightedVerifier> = from_json(
                query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::ActiveVerifiers {
                        service_name: service_name.into(),
                        chain_name: chain,
                    },
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(verifiers, vec![]);
        }
    }

    /// If a bonded and authorized verifier deregisters support for the first chain among multiple chains,
    /// they should remain part of the active verifier set for all chains except the first one.
    #[test]
    fn register_for_multiple_chains_deregister_for_first_one() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond = Uint128::new(100);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond: min_verifier_bond.try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chains = vec![
            chain_name!("ethereum"),
            chain_name!("binance"),
            chain_name!("avalanche"),
        ];

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: chains.clone(),
            },
        );
        assert!(res.is_ok());

        // Deregister only the first chain
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chains[0].clone()],
            },
        );
        assert!(res.is_ok());

        // Verify that verifier is not associated with the deregistered chain
        let deregistered_chain = chains[0].clone();
        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name: deregistered_chain,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![]);

        // Verify that verifier is still associated with other chains
        for chain in chains.iter().skip(1) {
            let verifiers: Vec<WeightedVerifier> = from_json(
                query(
                    deps.as_ref(),
                    mock_env(),
                    QueryMsg::ActiveVerifiers {
                        service_name: service_name.into(),
                        chain_name: chain.clone(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(
                verifiers,
                vec![WeightedVerifier {
                    verifier_info: Verifier {
                        address: cosmos_addr!("verifier"),
                        bonding_state: BondingState::Bonded {
                            amount: min_verifier_bond.try_into().unwrap(),
                        },
                        authorization_state: AuthorizationState::Authorized,
                        service_name: service_name.into()
                    },
                    weight: VERIFIER_WEIGHT
                }]
            );
        }
    }

    /// If a bonded and authorized verifier registers support for one chain and later deregisters support for another chain,
    /// the active verifier set for the original chain should remain unaffected by the deregistration.
    #[test]
    fn register_support_for_a_chain_deregister_support_for_another_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let second_chain_name = chain_name!("avalanche");
        // Deregister support for another chain
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![second_chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifiers,
            vec![WeightedVerifier {
                verifier_info: Verifier {
                    address: cosmos_addr!("verifier"),
                    bonding_state: BondingState::Bonded {
                        amount: min_verifier_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: VERIFIER_WEIGHT
            }]
        );
    }

    /// If a bonded and authorized verifier registers, deregisters, and again registers their support for a single chain,
    /// the active verifier set of that chain should include the verifier.
    #[test]
    fn register_deregister_register_support_for_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        // Second support declaration
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifiers,
            vec![WeightedVerifier {
                verifier_info: Verifier {
                    address: cosmos_addr!("verifier"),
                    bonding_state: BondingState::Bonded {
                        amount: min_verifier_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: VERIFIER_WEIGHT
            }]
        );
    }

    /// If a bonded and authorized verifier deregisters their support for a chain they have not previously registered
    /// support for, the call should be ignored and the active verifier set of the chain should be intact.
    #[test]
    fn deregister_previously_unsupported_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![])
    }

    /// If an unbonded but authorized verifier deregisters support for a chain they previously registered support for,
    /// that verifier should not be part of the active verifier set for that chain.
    #[test]
    fn register_and_deregister_support_for_single_chain_unbonded() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![]);
    }

    /// If a verifier registers support for a chain of an unregistered service,
    /// process should return a contract error of type ServiceNotFound.
    #[test]
    fn register_single_chain_for_nonexistent_service() {
        let mut deps = setup();

        let service_name = "validators";
        let chain_name = chain_name!("ethereum");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap_err();

        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::ServiceNotFound
        ));
    }

    /// If a verifier deregisters support for a chain of an unregistered service,
    /// process should return a contract error of type ServiceNotFound.
    #[test]
    fn deregister_single_chain_for_nonexistent_service() {
        let mut deps = setup();

        let service_name = "validators";
        let chain_name = chain_name!("ethereum");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap_err();

        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::ServiceNotFound
        ));
    }

    /// If a verifier that is not part of a service registers support for a chain from that specific service,
    /// process should return a contract error of type VerifierNotFound.
    #[test]
    fn register_from_unbonded_and_unauthorized_verifier_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap_err();

        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::VerifierNotFound
        ));
    }

    /// If a verifier that is not part of a service deregisters support for a chain from that specific service,
    /// process should return a contract error of type VerifierNotFound.
    #[test]
    fn deregister_from_unregistered_verifier_single_chain() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap_err();

        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::VerifierNotFound
        ));

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![]);
    }

    #[test]
    fn unbond_verifier() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::UnbondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![])
    }

    #[test]
    fn bond_wrong_denom() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128(), "funnydenom"),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        )
        .unwrap_err();

        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::WrongDenom
        ));
    }

    #[test]
    fn bond_but_not_authorized() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![])
    }

    #[test]
    fn bond_but_not_enough() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128() / 2, AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(verifiers, vec![])
    }

    #[test]
    fn bond_before_authorize() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifiers,
            vec![WeightedVerifier {
                verifier_info: Verifier {
                    address: cosmos_addr!("verifier"),
                    bonding_state: BondingState::Bonded {
                        amount: min_verifier_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: VERIFIER_WEIGHT
            }]
        );
    }

    #[test]
    fn unbond_then_rebond() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::UnbondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let verifiers: Vec<WeightedVerifier> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name,
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            verifiers,
            vec![WeightedVerifier {
                verifier_info: Verifier {
                    address: cosmos_addr!("verifier"),
                    bonding_state: BondingState::Bonded {
                        amount: min_verifier_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: VERIFIER_WEIGHT
            }]
        );
    }

    #[test]
    fn unbonding_period() {
        let mut deps = setup();

        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let service_name = "validators";
        let unbonding_period_days = 1;

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chain_name = chain_name!("ethereum");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name],
            },
        );
        assert!(res.is_ok());

        let mut unbond_request_env = mock_env();
        unbond_request_env.block.time = unbond_request_env.block.time.plus_days(1);

        let res = execute(
            deps.as_mut(),
            unbond_request_env.clone(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::UnbondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Response::new());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::ClaimStake {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            axelar_wasm_std::error::ContractError::from(ContractError::InvalidBondingState(
                BondingState::Unbonding {
                    unbonded_at: unbond_request_env.block.time,
                    amount: min_verifier_bond,
                }
            ))
            .to_string()
        );

        let mut after_unbond_period_env = mock_env();
        after_unbond_period_env.block.time = unbond_request_env
            .block
            .time
            .plus_days((unbonding_period_days + 1).into());

        let res = execute(
            deps.as_mut(),
            after_unbond_period_env,
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::ClaimStake {
                service_name: service_name.into(),
            },
        )
        .unwrap();
        assert_eq!(res.messages.len(), 1);
        assert_eq!(
            res.messages[0].msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: cosmos_addr!("verifier").to_string(),
                amount: coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION)
            })
        )
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn active_verifiers_should_not_return_less_than_min() {
        let mut deps = setup();

        let verifiers = vec![cosmos_addr!("verifier1"), cosmos_addr!("verifier2")];
        let min_num_verifiers = verifiers.len() as u16;

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        )
        .unwrap();

        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: verifiers.iter().map(|w| w.into()).collect(),
                service_name: service_name.into(),
            },
        )
        .unwrap();

        let chain_name = chain_name!("ethereum");

        for verifier in &verifiers {
            // should return err until all verifiers are registered
            let res = query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name: chain_name.clone(),
                },
            );
            assert!(res.is_err());

            let _ = execute(
                deps.as_mut(),
                mock_env(),
                message_info(
                    verifier,
                    &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
                ),
                ExecuteMsg::BondVerifier {
                    service_name: service_name.into(),
                },
            )
            .unwrap();

            let _ = execute(
                deps.as_mut(),
                mock_env(),
                message_info(verifier, &[]),
                ExecuteMsg::RegisterChainSupport {
                    service_name: service_name.into(),
                    chains: vec![chain_name.clone()],
                },
            )
            .unwrap();
        }

        // all verifiers registered, should not return err now
        let res: StdResult<Vec<WeightedVerifier>> = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::ActiveVerifiers {
                    service_name: service_name.into(),
                    chain_name: chain_name.clone(),
                },
            )
            .unwrap(),
        );
        assert!(res.is_ok());

        // remove one, should return err again
        let _ = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&verifiers[0], &[]),
            ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap();
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::ActiveVerifiers {
                service_name: service_name.into(),
                chain_name: chain_name.clone(),
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn jail_verifier() {
        let mut deps = setup();

        // register a service
        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let unbonding_period_days = 10;
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        // given a bonded verifier
        let verifier1 = cosmos_addr!("verifier-1");
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &verifier1,
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        // when verifier is jailed
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::JailVerifiers {
                verifiers: vec![verifier1.clone().into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        // verifier cannot unbond
        let err = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&verifier1, &[]),
            ExecuteMsg::UnbondVerifier {
                service_name: service_name.into(),
            },
        )
        .unwrap_err();
        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::VerifierJailed
        ));

        // given a verifier passed unbonding period
        let verifier2 = cosmos_addr!("verifier-2");

        // bond verifier
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &verifier2,
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let mut unbond_request_env = mock_env();
        unbond_request_env.block.time = unbond_request_env.block.time.plus_days(1);

        // unbond verifier
        let res = execute(
            deps.as_mut(),
            unbond_request_env.clone(),
            message_info(&verifier2, &[]),
            ExecuteMsg::UnbondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());
        let verifier2_details: VerifierDetails = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Verifier {
                    service_name: service_name.into(),
                    verifier: verifier2.to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let verifier = verifier2_details.verifier;

        assert_eq!(
            verifier.bonding_state,
            BondingState::Unbonding {
                amount: min_verifier_bond,
                unbonded_at: unbond_request_env.block.time,
            }
        );

        // when verifier is jailed
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::JailVerifiers {
                verifiers: vec![verifier2.clone().into()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        // and unbonding period has passed
        let mut after_unbond_period_env = mock_env();
        after_unbond_period_env.block.time = unbond_request_env
            .block
            .time
            .plus_days((unbonding_period_days + 1).into());

        // verifier cannot claim stake
        let err = execute(
            deps.as_mut(),
            after_unbond_period_env,
            message_info(&verifier2, &[]),
            ExecuteMsg::ClaimStake {
                service_name: service_name.into(),
            },
        )
        .unwrap_err();
        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::VerifierJailed
        ));
    }

    #[test]
    fn get_single_verifier_details() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(100),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier").to_string()],
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(
                &cosmos_addr!("verifier"),
                &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
            ),
            ExecuteMsg::BondVerifier {
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let chains = vec![
            chain_name!("ethereum"),
            chain_name!("binance"),
            chain_name!("avalanche"),
        ];
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("verifier"), &[]),
            ExecuteMsg::RegisterChainSupport {
                service_name: service_name.into(),
                chains: chains.clone(),
            },
        );
        assert!(res.is_ok());

        let verifier_details: VerifierDetails = from_json(
            query(
                deps.as_ref(),
                mock_env(),
                QueryMsg::Verifier {
                    service_name: service_name.into(),
                    verifier: cosmos_addr!("verifier").to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            verifier_details.verifier,
            Verifier {
                address: cosmos_addr!("verifier"),
                bonding_state: BondingState::Bonded {
                    amount: min_verifier_bond
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: service_name.into()
            }
        );
        assert_eq!(verifier_details.weight, VERIFIER_WEIGHT);

        let expected_chains: HashSet<ChainName> = chains.into_iter().collect();
        let actual_chains: HashSet<ChainName> =
            verifier_details.supported_chains.into_iter().collect();
        assert_eq!(expected_chains, actual_chains);
    }

    #[test]
    fn max_verifiers_limit_is_enforced_when_authorized_verifiers() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let max_verifiers = 4;

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(max_verifiers),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let verifiers_1 = vec![
            cosmos_addr!("verifier1").to_string(),
            cosmos_addr!("verifier2").to_string(),
            cosmos_addr!("verifier3").to_string(),
        ];

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: verifiers_1.clone(),
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let verifiers_2 = vec![
            cosmos_addr!("verifier4").to_string(),
            cosmos_addr!("verifier5").to_string(),
        ];

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: verifiers_2.clone(),
                service_name: service_name.into(),
            },
        );

        let err = res.unwrap_err();

        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::VerifierLimitExceeded
        ));
    }

    #[test]
    fn update_service_max_verifiers_only_succeed_if_below_current_authorized_verifier() {
        let mut deps = setup();

        let service_name = "validators";
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(5),
                min_verifier_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        let verifiers = vec![
            cosmos_addr!("verifier1").to_string(),
            cosmos_addr!("verifier2").to_string(),
            cosmos_addr!("verifier3").to_string(),
        ];

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: verifiers.clone(),
                service_name: service_name.into(),
            },
        );
        assert!(res.is_ok());

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::UpdateService {
                service_name: service_name.into(),
                updated_service_params: UpdatedServiceParams {
                    min_num_verifiers: None,
                    max_num_verifiers: Some(Some(2)),
                    min_verifier_bond: None,
                    unbonding_period_days: None,
                },
            },
        );

        let err = res.unwrap_err();
        assert!(err_contains!(
            err.report,
            ContractError,
            ContractError::MaxVerifiersSetBelowCurrent(2, 3)
        ));

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::UpdateService {
                service_name: service_name.into(),
                updated_service_params: UpdatedServiceParams {
                    min_num_verifiers: None,
                    max_num_verifiers: Some(Some(4)),
                    min_verifier_bond: None,
                    unbonding_period_days: None,
                },
            },
        );
        assert!(res.is_ok());
    }

    #[test]
    fn register_service_initializes_with_zero_authorized_verifiers() {
        let mut deps = setup();
        let service_name = "validators";

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                coordinator_contract: cosmos_addr!("coordinator").to_string(),
                min_num_verifiers: 0,
                max_num_verifiers: Some(10),
                min_verifier_bond: Uint128::new(100).try_into().unwrap(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        );
        assert!(res.is_ok());

        assert_auth_verifier_count_is_valid(&deps, &service_name.to_string(), 0);
    }

    #[test]
    fn re_authorizing_same_verifiers_does_not_increase_count() {
        let (mut deps, _api, service_name, _verifiers) = setup_service_with_5_verifiers();

        assert_auth_verifier_count_is_valid(&deps, &service_name.clone(), 5);
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![
                    cosmos_addr!("verifier1").to_string(),
                    cosmos_addr!("verifier2").to_string(),
                ],
                service_name: service_name.clone(),
            },
        );
        assert!(res.is_ok());
        assert_auth_verifier_count_is_valid(&deps, &service_name, 5);
    }

    #[test]
    fn unauthorize_verifiers_reduces_count() {
        let (mut deps, _api, service_name, _verifiers) = setup_service_with_5_verifiers();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::UnauthorizeVerifiers {
                verifiers: vec![
                    cosmos_addr!("verifier1").to_string(),
                    cosmos_addr!("verifier3").to_string(),
                ],
                service_name: service_name.clone(),
            },
        );
        assert!(res.is_ok());
        assert_auth_verifier_count_is_valid(&deps, &service_name, 3);
    }

    #[test]
    fn jailing_and_unjailing_authorized_verifier_affects_authorized_count() {
        let (mut deps, _api, service_name, _verifiers) = setup_service_with_5_verifiers();

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::JailVerifiers {
                verifiers: vec![cosmos_addr!("verifier2").to_string()],
                service_name: service_name.clone(),
            },
        );
        assert!(res.is_ok());
        assert_auth_verifier_count_is_valid(&deps, &service_name.clone(), 4);

        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::AuthorizeVerifiers {
                verifiers: vec![cosmos_addr!("verifier2").to_string()],
                service_name: service_name.clone(),
            },
        );
        assert!(res.is_ok());
        assert_auth_verifier_count_is_valid(&deps, &service_name, 5);
    }

    #[test]
    fn jailing_from_none_does_not_affect_count() {
        let (mut deps, _api, service_name, _verifiers) = setup_service_with_5_verifiers();

        let new_verifier = cosmos_addr!("verifier6").to_string();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::JailVerifiers {
                verifiers: vec![new_verifier],
                service_name: service_name.clone(),
            },
        );
        assert!(res.is_ok());
        assert_auth_verifier_count_is_valid(&deps, &service_name, 5);
    }

    #[test]
    fn jailing_unauthorized_verifier_does_not_affect_authorized_count() {
        let (mut deps, _api, service_name, _verifiers) = setup_service_with_5_verifiers();

        let new_verifier = cosmos_addr!("verifier6").to_string();
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::JailVerifiers {
                verifiers: vec![new_verifier],
                service_name: service_name.clone(),
            },
        );
        assert!(res.is_ok());
        assert_auth_verifier_count_is_valid(&deps, &service_name, 5);
    }

    #[test]
    fn active_verifiers_respects_chain_max_override() {
        let (mut deps, api, service_name, original_verifiers) = setup_service_with_5_verifiers();
        let min_verifier_bond: nonempty::Uint128 = Uint128::new(100).try_into().unwrap();
        let chain_name = chain_name!("ethereum");

        // Bond and register all verifiers
        for verifier in &original_verifiers {
            let res = execute(
                deps.as_mut(),
                mock_env(),
                message_info(
                    &api.addr_validate(verifier).unwrap(),
                    &coins(min_verifier_bond.into_inner().u128(), AXL_DENOMINATION),
                ),
                ExecuteMsg::BondVerifier {
                    service_name: service_name.clone(),
                },
            );
            assert!(res.is_ok());

            let res = execute(
                deps.as_mut(),
                mock_env(),
                message_info(&api.addr_validate(verifier).unwrap(), &[]),
                ExecuteMsg::RegisterChainSupport {
                    service_name: service_name.clone(),
                    chains: vec![chain_name.clone()],
                },
            );
            assert!(res.is_ok());
        }

        // Create chain override with max verifiers = 3 (smaller than global max of 10)
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::OverrideServiceParams {
                service_name: service_name.clone(),
                chain_name: chain_name.clone(),
                service_params_override: crate::msg::ServiceParamsOverride {
                    min_num_verifiers: None,
                    max_num_verifiers: Some(Some(3)), // Chain limit of 3
                },
            },
        );
        assert!(res.is_ok());

        // Query active verifiers for the chain
        let active_verifiers = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::ActiveVerifiers {
                service_name: service_name.clone(),
                chain_name: chain_name.clone(),
            },
        )
        .unwrap();

        let active_verifiers: Vec<WeightedVerifier> = from_json(&active_verifiers).unwrap();

        // Should only return 3 verifiers (respecting chain max override)
        assert_eq!(active_verifiers.len(), 3);

        // Increase the max verifiers, make sure the full set is returned
        let res = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!("governance"), &[]),
            ExecuteMsg::OverrideServiceParams {
                service_name: service_name.clone(),
                chain_name: chain_name.clone(),
                service_params_override: crate::msg::ServiceParamsOverride {
                    min_num_verifiers: None,
                    max_num_verifiers: Some(Some(5)), // Chain limit of 3
                },
            },
        );
        assert!(res.is_ok());

        // Query active verifiers for the chain
        let active_verifiers = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::ActiveVerifiers {
                service_name: service_name.clone(),
                chain_name: chain_name.clone(),
            },
        )
        .unwrap();

        let active_verifiers: Vec<WeightedVerifier> = from_json(&active_verifiers).unwrap();

        assert_eq!(active_verifiers.len(), original_verifiers.len());

        // Test that without chain override, all 5 verifiers would be returned
        let chain_name_no_override = chain_name!("polygon");

        // Register all verifiers for the chain without override
        for verifier in &original_verifiers {
            let res = execute(
                deps.as_mut(),
                mock_env(),
                message_info(&api.addr_validate(verifier).unwrap(), &[]),
                ExecuteMsg::RegisterChainSupport {
                    service_name: service_name.clone(),
                    chains: vec![chain_name_no_override.clone()],
                },
            );
            assert!(res.is_ok());
        }

        let active_verifiers_no_override = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::ActiveVerifiers {
                service_name: service_name.clone(),
                chain_name: chain_name_no_override,
            },
        )
        .unwrap();

        let active_verifiers_no_override: Vec<WeightedVerifier> =
            from_json(&active_verifiers_no_override).unwrap();

        // Should return all 5 verifiers (respecting global max of 10)
        assert_eq!(active_verifiers_no_override.len(), 5);
    }
}

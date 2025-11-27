#[cfg(test)]
mod legacy_state;

use axelar_wasm_std::migrate_from_version;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Empty, Env, Response};

use crate::state::update_authorized_verifier_count;

pub type MigrateMsg = Empty;

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.2")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    update_authorized_verifier_count(deps.storage)?;
    Ok(Response::default())
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::nonempty::Uint128;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env, MockApi, MockQuerier};
    use cosmwasm_std::{Env, MemoryStorage, MessageInfo, OwnedDeps};
    use error_stack::Result;
    use router_api::cosmos_addr;
    use service_registry_api::error::ContractError;
    use service_registry_api::{AuthorizationState, Service};

    use crate::contract::execute::update_verifier_authorization_status;
    use crate::contract::migrations::legacy_state::save_new_service as legacy_save_new_service;
    use crate::contract::{instantiate, migrate, MigrateMsg};
    use crate::msg::InstantiateMsg;
    use crate::state::{number_of_authorized_verifiers, save_new_service};

    const GOVERNANCE: &str = "governance";
    const COORDINATOR: &str = "coordinator";
    const SENDER: &str = "sender";
    const VERIFIER1: &str = "verifier1";

    fn init() -> (
        OwnedDeps<MemoryStorage, MockApi, MockQuerier>,
        Env,
        MessageInfo,
        Service,
    ) {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&cosmos_addr!(SENDER), &[]);

        assert!(instantiate(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            InstantiateMsg {
                governance_account: cosmos_addr!(GOVERNANCE).to_string(),
            },
        )
        .is_ok());

        let service_name = "validators".to_string();
        let service = Service {
            name: service_name.clone(),
            min_num_verifiers: 1,
            max_num_verifiers: Some(5),
            min_verifier_bond: Uint128::try_from(100u128).unwrap(),
            unbonding_period_days: 0,
            bond_denom: "uamplifier".to_string(),
            coordinator_contract: cosmos_addr!(COORDINATOR),
            description: "description".to_string(),
        };

        (deps, env, info, service)
    }

    fn legacy_setup() -> (
        OwnedDeps<MemoryStorage, MockApi, MockQuerier>,
        Env,
        MessageInfo,
        Service,
    ) {
        let (mut deps, env, info, service) = init();

        let res: Result<Service, ContractError> =
            legacy_save_new_service(deps.as_mut().storage, &service.name, service.clone());
        assert!(res.is_ok(), "cannot save service");

        (deps, env, info, service)
    }

    fn setup() -> (
        OwnedDeps<MemoryStorage, MockApi, MockQuerier>,
        Env,
        MessageInfo,
        Service,
    ) {
        let (mut deps, env, info, service) = init();

        let res: Result<Service, ContractError> =
            save_new_service(deps.as_mut().storage, &service.name, service.clone());
        assert!(res.is_ok(), "cannot save service");

        (deps, env, info, service)
    }

    #[test]
    fn migrate_add_count_for_missing_service_succeeds() {
        let (mut deps, env, _info, service) = legacy_setup();

        let res = update_verifier_authorization_status(
            deps.as_mut(),
            vec![cosmos_addr!(VERIFIER1)],
            service.name.clone(),
            AuthorizationState::Authorized,
        );
        assert!(res.is_err());

        assert!(migrate(deps.as_mut(), env, MigrateMsg {},).is_ok());

        let res = update_verifier_authorization_status(
            deps.as_mut(),
            vec![cosmos_addr!(VERIFIER1)],
            service.name.clone(),
            AuthorizationState::Authorized,
        );
        assert!(res.is_ok());

        assert_eq!(
            number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap(),
            1u16
        );
    }

    #[test]
    fn migrate_does_not_modify_count_for_existing_service_succeeds() {
        let (mut deps, env, _info, service) = setup();

        assert_eq!(
            number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap(),
            0u16
        );

        let res = update_verifier_authorization_status(
            deps.as_mut(),
            vec![cosmos_addr!(VERIFIER1)],
            service.name.clone(),
            AuthorizationState::Authorized,
        );
        assert!(res.is_ok());

        assert_eq!(
            number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap(),
            1u16
        );

        assert!(migrate(deps.as_mut(), env, MigrateMsg {},).is_ok());

        // Migration must not alter existing authorized verifier count
        assert_eq!(
            number_of_authorized_verifiers(deps.as_ref().storage, &service.name).unwrap(),
            1u16
        );
    }
}

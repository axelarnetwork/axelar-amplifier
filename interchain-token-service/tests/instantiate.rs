use std::collections::HashMap;

use assert_ok::assert_ok;
use axelar_wasm_std::permission_control::Permission;
use axelar_wasm_std::{assert_err_contains, permission_control};
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use cosmwasm_std::Addr;
use interchain_token_service::contract;
use interchain_token_service::msg::InstantiateMsg;
use utils::params;

mod utils;

#[test]
fn instantiate_succeeds() {
    let mut deps = mock_dependencies();
    let response = assert_ok!(utils::instantiate_contract(deps.as_mut()));
    goldie::assert_json!(response);
}

#[test]
fn instantiate_with_args_succeeds() {
    let mut deps = mock_dependencies();

    let its_contracts = vec![
        ("ethereum".parse().unwrap(), "eth-address".parse().unwrap()),
        ("optimism".parse().unwrap(), "op-address".parse().unwrap()),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();

    let mut response = assert_ok!(contract::instantiate(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &[]),
        InstantiateMsg {
            governance_address: params::GOVERNANCE.to_string(),
            admin_address: params::ADMIN.to_string(),
            axelarnet_gateway_address: params::GATEWAY.to_string(),
            its_contracts: its_contracts.clone(),
        },
    ));

    response.events.sort_by_key(|event| {
        event
            .attributes
            .iter()
            .find(|attr| attr.key == "chain")
            .map(|attr| attr.value.clone())
            .unwrap_or_default()
    });

    assert_eq!(0, response.messages.len());
    goldie::assert_json!(response);

    assert_eq!(
        assert_ok!(permission_control::sender_role(
            deps.as_ref().storage,
            &Addr::unchecked(params::ADMIN)
        )),
        Permission::Admin.into()
    );
    assert_eq!(
        assert_ok!(permission_control::sender_role(
            deps.as_ref().storage,
            &Addr::unchecked(params::GOVERNANCE)
        )),
        Permission::Governance.into()
    );

    let stored_its_contracts = assert_ok!(utils::query_all_its_contracts(deps.as_ref()));
    assert_eq!(stored_its_contracts, its_contracts);
}

#[test]
fn invalid_gateway_address() {
    let mut deps = mock_dependencies();
    let msg = InstantiateMsg {
        governance_address: utils::params::GOVERNANCE.to_string(),
        admin_address: utils::params::ADMIN.to_string(),
        axelarnet_gateway_address: "".to_string(),
        its_contracts: Default::default(),
    };
    assert_err_contains!(
        contract::instantiate(deps.as_mut(), mock_env(), mock_info("sender", &[]), msg),
        axelar_wasm_std::address::Error,
        axelar_wasm_std::address::Error::InvalidAddress(..)
    );
}

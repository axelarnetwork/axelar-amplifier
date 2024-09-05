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
    assert_ok!(utils::instantiate_contract(deps.as_mut()));
}

#[test]
fn instantiate_with_args_succeeds() {
    let mut deps = mock_dependencies();

    let its_addresses = vec![
        ("ethereum".parse().unwrap(), "eth-address".parse().unwrap()),
        ("optimism".parse().unwrap(), "op-address".parse().unwrap()),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();

    let response = assert_ok!(contract::instantiate(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &[]),
        InstantiateMsg {
            governance_address: params::GOVERNANCE.to_string(),
            admin_address: params::ADMIN.to_string(),
            axelarnet_gateway_address: params::GATEWAY.to_string(),
            its_addresses: its_addresses.clone(),
        },
    ));
    assert_eq!(0, response.messages.len());

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

    let stored_its_addresses = assert_ok!(utils::query_all_its_addresses(deps.as_ref()));
    assert_eq!(stored_its_addresses, its_addresses);
}

#[test]
fn invalid_gateway_address() {
    let mut deps = mock_dependencies();
    let msg = InstantiateMsg {
        governance_address: utils::params::GOVERNANCE.to_string(),
        admin_address: utils::params::ADMIN.to_string(),
        axelarnet_gateway_address: "".to_string(),
        its_addresses: Default::default(),
    };
    assert_err_contains!(
        contract::instantiate(deps.as_mut(), mock_env(), mock_info("sender", &[]), msg),
        axelar_wasm_std::address::Error,
        axelar_wasm_std::address::Error::InvalidAddress(..)
    );
}

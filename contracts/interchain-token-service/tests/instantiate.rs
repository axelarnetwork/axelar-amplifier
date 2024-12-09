use assert_ok::assert_ok;
use axelar_wasm_std::permission_control::Permission;
use axelar_wasm_std::{assert_err_contains, permission_control};
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info, MockApi};
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
    let governance_address = deps.api.addr_make(params::GOVERNANCE);
    let admin_address = deps.api.addr_make(params::ADMIN);
    let axelarnet_gateway_address = deps.api.addr_make(params::GATEWAY);

    let mut response = assert_ok!(contract::instantiate(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &[]),
        InstantiateMsg {
            governance_address: governance_address.to_string(),
            admin_address: admin_address.to_string(),
            axelarnet_gateway_address: axelarnet_gateway_address.to_string(),
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
            &MockApi::default().addr_make(params::ADMIN)
        )),
        Permission::Admin.into()
    );
    assert_eq!(
        assert_ok!(permission_control::sender_role(
            deps.as_ref().storage,
            &MockApi::default().addr_make(params::GOVERNANCE)
        )),
        Permission::Governance.into()
    );
}

#[test]
fn invalid_gateway_address() {
    let mut deps = mock_dependencies();
    let msg = InstantiateMsg {
        governance_address: utils::params::GOVERNANCE.to_string(),
        admin_address: utils::params::ADMIN.to_string(),
        axelarnet_gateway_address: "".to_string(),
    };
    assert_err_contains!(
        contract::instantiate(deps.as_mut(), mock_env(), mock_info("sender", &[]), msg),
        axelar_wasm_std::address::Error,
        axelar_wasm_std::address::Error::InvalidAddress(..)
    );
}

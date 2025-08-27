use assert_ok::assert_ok;
use axelar_wasm_std::permission_control::Permission;
use axelar_wasm_std::{assert_err_contains, permission_control};
use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
use interchain_token_service::contract;
use interchain_token_service::msg::InstantiateMsg;
use router_api::cosmos_addr;

use crate::utils::params;

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
    let governance_address = cosmos_addr!(params::GOVERNANCE);
    let admin_address = cosmos_addr!(params::ADMIN);
    let axelarnet_gateway_address = cosmos_addr!(params::GATEWAY);
    let operator_address = cosmos_addr!(params::OPERATOR);

    let mut response = assert_ok!(contract::instantiate(
        deps.as_mut(),
        mock_env(),
        message_info(&cosmos_addr!(params::SENDER), &[]),
        InstantiateMsg {
            governance_address: governance_address.to_string(),
            admin_address: admin_address.to_string(),
            axelarnet_gateway_address: axelarnet_gateway_address.to_string(),
            operator_address: operator_address.to_string(),
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
            &cosmos_addr!(params::ADMIN)
        )),
        Permission::Admin.into()
    );
    assert_eq!(
        assert_ok!(permission_control::sender_role(
            deps.as_ref().storage,
            &cosmos_addr!(params::GOVERNANCE)
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
        operator_address: utils::params::OPERATOR.to_string(),
    };
    assert_err_contains!(
        contract::instantiate(
            deps.as_mut(),
            mock_env(),
            message_info(&cosmos_addr!(params::SENDER), &[]),
            msg
        ),
        axelar_wasm_std::address::Error,
        axelar_wasm_std::address::Error::InvalidAddress(..)
    );
}

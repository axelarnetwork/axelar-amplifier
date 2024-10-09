use assert_ok::assert_ok;
use axelar_wasm_std::assert_err_contains;
use axelarnet_gateway::contract;
use axelarnet_gateway::msg::InstantiateMsg;
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

use crate::utils::{instantiate_contract, params};

mod utils;
#[test]
fn instantiate_works() {
    let mut deps = mock_dependencies();

    assert_ok!(instantiate_contract(deps.as_mut()));
}

#[test]
fn invalid_router_address() {
    let mut deps = mock_dependencies();

    let msg = InstantiateMsg {
        chain_name: params::AXELARNET.parse().unwrap(),
        router_address: "".to_string(),
        nexus: params::NEXUS.parse().unwrap(),
    };

    assert_err_contains!(
        contract::instantiate(deps.as_mut(), mock_env(), mock_info("sender", &[]), msg),
        axelar_wasm_std::address::Error,
        axelar_wasm_std::address::Error::InvalidAddress(..),
    );
}

#[test]
fn invalid_nexus_module_address() {
    let mut deps = mock_dependencies();

    let msg = InstantiateMsg {
        chain_name: params::AXELARNET.parse().unwrap(),
        router_address: params::ROUTER.parse().unwrap(),
        nexus: "".to_string(),
    };

    assert_err_contains!(
        contract::instantiate(deps.as_mut(), mock_env(), mock_info("sender", &[]), msg),
        axelar_wasm_std::address::Error,
        axelar_wasm_std::address::Error::InvalidAddress(..),
    );
}

use axelarnet_gateway::contract;
use axelarnet_gateway::msg::InstantiateMsg;
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

use crate::utils::{instantiate_contract, params};

mod utils;
#[test]
fn instantiate_works() {
    let mut deps = mock_dependencies();

    assert!(instantiate_contract(deps.as_mut()).is_ok());
}

#[test]
fn invalid_router_address() {
    let mut deps = mock_dependencies();

    let msg = InstantiateMsg {
        chain_name: params::AXELARNET.parse().unwrap(),
        router_address: "".to_string(),
    };

    assert!(
        contract::instantiate(deps.as_mut(), mock_env(), mock_info("sender", &[]), msg).is_err()
    );
}

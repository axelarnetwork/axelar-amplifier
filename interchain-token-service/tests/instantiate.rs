use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use interchain_token_service::contract;
use interchain_token_service::msg::InstantiateMsg;

mod utils;

#[test]
fn instantiate_works() {
    let mut deps = mock_dependencies();
    assert!(utils::instantiate_contract(deps.as_mut()).is_ok());
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
    assert!(
        contract::instantiate(deps.as_mut(), mock_env(), mock_info("sender", &[]), msg).is_err()
    );
}

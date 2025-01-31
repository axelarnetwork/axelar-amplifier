use std::collections::HashMap;

use assert_ok::assert_ok;
use cosmwasm_std::testing::mock_dependencies;
use cosmwasm_std::Uint256;
use interchain_token_service::msg::{ChainConfigResponse, TruncationConfig};
use interchain_token_service::TokenId;
use router_api::{Address, ChainNameRaw};

mod utils;

#[test]
fn query_chain_config() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainNameRaw = "Ethereum".parse().unwrap();
    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    utils::register_chain(
        deps.as_mut(),
        chain.clone(),
        address.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();

    let original_chain_config = ChainConfigResponse {
        chain: chain.clone(),
        its_edge_contract: address.clone(),
        truncation: TruncationConfig {
            max_uint: Uint256::MAX.try_into().unwrap(),
            max_decimals_when_truncating: u8::MAX,
        },
        frozen: false,
    };

    let chain_config = assert_ok!(utils::query_its_chain(deps.as_ref(), chain.clone()));
    assert_eq!(chain_config.unwrap(), original_chain_config);

    // case sensitive query
    let chain_config = assert_ok!(utils::query_its_chain(
        deps.as_ref(),
        "ethereum".parse().unwrap()
    ));
    assert_eq!(chain_config, None);

    let new_address: Address = "0x9999999990123456789012345678901234567890"
        .parse()
        .unwrap();
    assert_ok!(utils::update_chain(
        deps.as_mut(),
        chain.clone(),
        new_address.clone()
    ));

    let chain_config = assert_ok!(utils::query_its_chain(deps.as_ref(), chain.clone()));
    assert_eq!(chain_config.unwrap().its_edge_contract, new_address);

    let non_existent_chain: ChainNameRaw = "non-existent-chain".parse().unwrap();
    let chain_config = assert_ok!(utils::query_its_chain(deps.as_ref(), non_existent_chain));
    assert_eq!(chain_config, None);
}

#[test]
fn query_all_its_contracts() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let its_contracts = vec![
        (
            "ethereum".parse::<ChainNameRaw>().unwrap(),
            "0x1234567890123456789012345678901234567890"
                .parse::<Address>()
                .unwrap(),
        ),
        (
            "Optimism".parse().unwrap(),
            "0x0987654321098765432109876543210987654321"
                .parse()
                .unwrap(),
        ),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();

    for (chain, address) in its_contracts.iter() {
        utils::register_chain(
            deps.as_mut(),
            chain.clone(),
            address.clone(),
            Uint256::MAX.try_into().unwrap(),
            u8::MAX,
        )
        .unwrap();
    }

    let queried_addresses = assert_ok!(utils::query_all_its_contracts(deps.as_ref()));
    assert_eq!(queried_addresses, its_contracts);
}

#[test]
fn query_token_chain_config() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainNameRaw = "ethereum".parse().unwrap();
    let token_id: TokenId = TokenId::new([1; 32]);

    let config = utils::query_token_instance(deps.as_ref(), chain, token_id).unwrap();
    assert_eq!(config, None);
}

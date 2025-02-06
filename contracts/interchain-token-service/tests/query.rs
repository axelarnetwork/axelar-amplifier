use std::collections::HashMap;

use assert_ok::assert_ok;
use cosmwasm_std::testing::mock_dependencies;
use cosmwasm_std::Uint256;
use interchain_token_service::msg::{
    ChainConfigResponse, ChainFilter, ChainStatusFilter, TruncationConfig,
};
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

#[test]
fn query_contract_enable_disable_lifecycle() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let enabled = utils::query_is_contract_enabled(deps.as_ref()).unwrap();
    assert!(enabled);

    utils::disable_contract_execution(deps.as_mut()).unwrap();

    let enabled = utils::query_is_contract_enabled(deps.as_ref()).unwrap();
    assert!(!enabled);
}

#[test]
fn query_chains_config() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let eth_chain: ChainNameRaw = "Ethereum".parse().unwrap();
    let eth_address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    utils::register_chain(
        deps.as_mut(),
        eth_chain.clone(),
        eth_address.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();

    let poly_chain: ChainNameRaw = "Polygon".parse().unwrap();
    let poly_address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    utils::register_chain(
        deps.as_mut(),
        poly_chain.clone(),
        poly_address.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();

    // no filtering
    let all_chain_configs = assert_ok!(utils::query_its_chains(deps.as_ref(), None));
    let expected_chain_configs = [
        utils::create_expected_chain_config(
            eth_chain.clone(),
            eth_address.clone(),
            Uint256::MAX.try_into().unwrap(),
            u8::MAX,
            false,
        ),
        utils::create_expected_chain_config(
            poly_chain.clone(),
            poly_address.clone(),
            Uint256::MAX.try_into().unwrap(),
            u8::MAX,
            false,
        ),
    ];
    utils::field_by_field_check(all_chain_configs, expected_chain_configs.to_vec());

    // filter active chains, should be the same as all chains
    let active_chain_configs = assert_ok!(utils::query_its_chains(
        deps.as_ref(),
        Some(ChainFilter {
            frozen_status: Some(ChainStatusFilter::Active),
        })
    ));
    utils::field_by_field_check(active_chain_configs, expected_chain_configs.to_vec());

    // filter frozen chains, should be empty
    let frozen_chain_configs = assert_ok!(utils::query_its_chains(
        deps.as_ref(),
        Some(ChainFilter {
            frozen_status: Some(ChainStatusFilter::Frozen),
        })
    ));
    assert_eq!(frozen_chain_configs, vec![]);

    // freeze a chain and query again
    utils::freeze_chain(deps.as_mut(), eth_chain.clone()).unwrap();
    let frozen_chain_configs = assert_ok!(utils::query_its_chains(
        deps.as_ref(),
        Some(ChainFilter {
            frozen_status: Some(ChainStatusFilter::Frozen),
        })
    ));
    let expected_frozen_chain_configs = [utils::create_expected_chain_config(
        eth_chain,
        eth_address,
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
        true,
    )];
    assert_eq!(frozen_chain_configs, expected_frozen_chain_configs);

    // filter for active chains after freeze
    let active_chain_configs = assert_ok!(utils::query_its_chains(
        deps.as_ref(),
        Some(ChainFilter {
            frozen_status: Some(ChainStatusFilter::Active),
        })
    ));
    let expected_active_chain_configs = [utils::create_expected_chain_config(
        poly_chain,
        poly_address,
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
        false,
    )];
    assert_eq!(active_chain_configs, expected_active_chain_configs);
}

use std::collections::HashMap;

use assert_ok::assert_ok;
use cosmwasm_std::testing::{mock_dependencies, MockApi, MockQuerier, MockStorage};
use cosmwasm_std::{from_json, Empty, OwnedDeps};
use interchain_token_service::msg::{
    ChainConfigResponse, ChainFilter, ChainStatusFilter, QueryMsg, TruncationConfig,
    DEFAULT_PAGINATION_LIMIT,
};
use interchain_token_api::TokenId;
use router_api::{Address, ChainNameRaw};

mod utils;

struct ChainConfigTest {
    deps: OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
    eth: utils::ChainData,
    polygon: utils::ChainData,
}

impl ChainConfigTest {
    fn setup() -> Self {
        let mut deps = mock_dependencies();
        utils::instantiate_contract(deps.as_mut()).unwrap();

        let eth = utils::ChainData {
            chain: "Ethereum".parse().unwrap(),
            address: "0x1234567890123456789012345678901234567890"
                .parse()
                .unwrap(),
            max_uint_bits: 256.try_into().unwrap(),
            max_decimals: 18,
        };

        let polygon = utils::ChainData {
            chain: "Polygon".parse().unwrap(),
            address: "0x1234567890123456789012345678901234567890"
                .parse()
                .unwrap(),
            max_uint_bits: 256.try_into().unwrap(),
            max_decimals: 18,
        };

        let mut test_config = Self { deps, eth, polygon };
        test_config.register_test_chains();
        test_config
    }

    fn register_test_chains(&mut self) {
        utils::register_chain(
            self.deps.as_mut(),
            self.eth.chain.clone(),
            self.eth.address.clone(),
            self.eth.max_uint_bits,
            self.eth.max_decimals,
        )
        .unwrap();

        utils::register_chain(
            self.deps.as_mut(),
            self.polygon.chain.clone(),
            self.polygon.address.clone(),
            self.polygon.max_uint_bits,
            self.polygon.max_decimals,
        )
        .unwrap();
    }
}

#[test]
fn query_chain_config() {
    let mut test_config = ChainConfigTest::setup();

    let eth_expected_config_response = ChainConfigResponse {
        chain: test_config.eth.chain.clone(),
        its_edge_contract: test_config.eth.address.clone(),
        truncation: TruncationConfig {
            max_uint_bits: test_config.eth.max_uint_bits,
            max_decimals_when_truncating: test_config.eth.max_decimals,
        },
        frozen: false,
        translation_contract: cosmwasm_std::testing::MockApi::default()
            .addr_make("translation_contract"),
    };

    let eth_chain_config = assert_ok!(utils::query_its_chain(
        test_config.deps.as_ref(),
        test_config.eth.chain.clone()
    ));
    assert_eq!(eth_chain_config.unwrap(), eth_expected_config_response);

    // case sensitive query
    let chain_config = assert_ok!(utils::query_its_chain(
        test_config.deps.as_ref(),
        "ethereum".parse().unwrap()
    ));
    assert_eq!(chain_config, None);

    let new_address: Address = "0x9999999990123456789012345678901234567890"
        .parse()
        .unwrap();
    assert_ok!(utils::update_chain(
        test_config.deps.as_mut(),
        test_config.eth.chain.clone(),
        new_address.clone(),
        128.try_into().unwrap(),
        18,
    ));

    let chain_config = assert_ok!(utils::query_its_chain(
        test_config.deps.as_ref(),
        test_config.eth.chain.clone()
    ));
    assert_eq!(chain_config.unwrap().its_edge_contract, new_address);

    let non_existent_chain: ChainNameRaw = "non-existent-chain".parse().unwrap();
    let chain_config = assert_ok!(utils::query_its_chain(
        test_config.deps.as_ref(),
        non_existent_chain
    ));
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
            256.try_into().unwrap(),
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
    let mut test_config = ChainConfigTest::setup();

    // Test all chains
    let all_chains = utils::query_its_chains(test_config.deps.as_ref(), None, None, 2).unwrap();
    let expected = vec![
        utils::create_config_response(&test_config.eth, false),
        utils::create_config_response(&test_config.polygon, false),
    ];
    utils::assert_configs_equal(&all_chains, &expected);

    // Test active chains
    let active_chains = utils::query_its_chains(
        test_config.deps.as_ref(),
        Some(ChainFilter {
            status: Some(ChainStatusFilter::Active),
        }),
        None,
        2,
    )
    .unwrap();
    utils::assert_configs_equal(&active_chains, &expected);

    // Test frozen chains (empty)
    let frozen_chains = utils::query_its_chains(
        test_config.deps.as_ref(),
        Some(ChainFilter {
            status: Some(ChainStatusFilter::Frozen),
        }),
        None,
        1,
    )
    .unwrap();
    assert!(frozen_chains.is_empty());

    // Test after freezing eth chain
    utils::freeze_chain(test_config.deps.as_mut(), test_config.eth.chain.clone()).unwrap();

    let frozen_chains = utils::query_its_chains(
        test_config.deps.as_ref(),
        Some(ChainFilter {
            status: Some(ChainStatusFilter::Frozen),
        }),
        None,
        1,
    )
    .unwrap();
    utils::assert_configs_equal(
        &frozen_chains,
        &[utils::create_config_response(&test_config.eth, true)],
    );

    let active_chains = utils::query_its_chains(
        test_config.deps.as_ref(),
        Some(ChainFilter {
            status: Some(ChainStatusFilter::Active),
        }),
        None,
        1,
    )
    .unwrap();
    utils::assert_configs_equal(
        &active_chains,
        &[utils::create_config_response(&test_config.polygon, false)],
    );
}

#[test]
fn query_chains_pagination() {
    let mut test_config = ChainConfigTest::setup();

    let chains = vec![
        ("Chain1", "0x1234567890123456789012345678901234567890"),
        ("Chain2", "0x1234567890123456789012345678901234567891"),
        ("Chain3", "0x1234567890123456789012345678901234567892"),
        ("Chain4", "0x1234567890123456789012345678901234567893"),
        ("Chain5", "0x1234567890123456789012345678901234567894"),
    ];

    for (chain_name, address) in chains {
        utils::register_chain(
            test_config.deps.as_mut(),
            chain_name.parse().unwrap(),
            address.parse().unwrap(),
            test_config.eth.max_uint_bits,
            test_config.eth.max_decimals,
        )
        .unwrap();
    }

    let first_page = utils::query_its_chains(test_config.deps.as_ref(), None, None, 2).unwrap();

    assert_eq!(first_page.len(), 2);
    let last_chain_name = first_page.last().unwrap().chain.clone();

    let second_page =
        utils::query_its_chains(test_config.deps.as_ref(), None, Some(last_chain_name), 2).unwrap();

    assert_eq!(second_page.len(), 2);
    assert_ne!(
        first_page.last().unwrap().chain,
        second_page.first().unwrap().chain
    );

    utils::freeze_chain(test_config.deps.as_mut(), "Chain1".parse().unwrap()).unwrap();
    utils::freeze_chain(test_config.deps.as_mut(), "Chain3".parse().unwrap()).unwrap();
    utils::freeze_chain(test_config.deps.as_mut(), "Chain5".parse().unwrap()).unwrap();

    let frozen_first_page = utils::query_its_chains(
        test_config.deps.as_ref(),
        Some(ChainFilter {
            status: Some(ChainStatusFilter::Frozen),
        }),
        None,
        2,
    )
    .unwrap();

    assert_eq!(frozen_first_page.len(), 2);
    let last_frozen_chain = frozen_first_page.last().unwrap().chain.clone();

    let frozen_second_page = utils::query_its_chains(
        test_config.deps.as_ref(),
        Some(ChainFilter {
            status: Some(ChainStatusFilter::Frozen),
        }),
        Some(last_frozen_chain),
        2,
    )
    .unwrap();

    assert_ne!(
        frozen_first_page.last().unwrap().chain,
        frozen_second_page.first().unwrap().chain
    );
    assert_eq!(frozen_second_page.len(), 1);
}

#[test]
fn test_empty_its_chains_query_deserialization() {
    let empty_query = r#"{"its_chains":{}}"#;

    let query_msg: QueryMsg = from_json(empty_query).unwrap();

    match query_msg {
        QueryMsg::ItsChains {
            filter,
            start_after,
            limit,
        } => {
            assert_eq!(filter, None);
            assert_eq!(start_after, None);
            assert_eq!(limit, DEFAULT_PAGINATION_LIMIT);
        }
        _ => panic!("Expected ItsChains variant"),
    }
}

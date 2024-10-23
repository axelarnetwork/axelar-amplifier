use std::collections::HashMap;

use assert_ok::assert_ok;
use cosmwasm_std::testing::mock_dependencies;
use router_api::{Address, ChainNameRaw};

mod utils;

#[test]
fn query_its_contract() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainNameRaw = "Ethereum".parse().unwrap();
    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    utils::register_its_contract(deps.as_mut(), chain.clone(), address.clone()).unwrap();

    let queried_address = assert_ok!(utils::query_its_contract(deps.as_ref(), chain.clone()));
    assert_eq!(queried_address, Some(address));

    // case sensitive query
    let queried_address = assert_ok!(utils::query_its_contract(
        deps.as_ref(),
        "ethereum".parse().unwrap()
    ));
    assert_eq!(queried_address, None);

    assert_ok!(utils::deregister_its_contract(deps.as_mut(), chain.clone()));

    let queried_address = assert_ok!(utils::query_its_contract(deps.as_ref(), chain.clone()));
    assert_eq!(queried_address, None);

    let non_existent_chain: ChainNameRaw = "non-existent-chain".parse().unwrap();
    let queried_address = assert_ok!(utils::query_its_contract(deps.as_ref(), non_existent_chain));
    assert_eq!(queried_address, None);
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
        utils::register_its_contract(deps.as_mut(), chain.clone(), address.clone()).unwrap();
    }

    let queried_addresses = assert_ok!(utils::query_all_its_contracts(deps.as_ref()));
    assert_eq!(queried_addresses, its_contracts);
}

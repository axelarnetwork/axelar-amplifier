use std::collections::HashMap;

use cosmwasm_std::testing::mock_dependencies;
use router_api::{Address, ChainName};

mod utils;

#[test]
fn query_its_address() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainName = "ethereum".parse().unwrap();
    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    let res = utils::set_its_address(deps.as_mut(), chain.clone(), address.clone());
    assert!(res.is_ok());

    let queried_address = utils::query_its_address(deps.as_ref(), chain.clone()).unwrap();
    assert_eq!(queried_address, Some(address));

    let res = utils::remove_its_address(deps.as_mut(), chain.clone());
    assert!(res.is_ok());

    let queried_address = utils::query_its_address(deps.as_ref(), chain.clone()).unwrap();
    assert_eq!(queried_address, None);

    // Query non-existent chain
    let non_existent_chain: ChainName = "non-existent-chain".parse().unwrap();
    let queried_address = utils::query_its_address(deps.as_ref(), non_existent_chain).unwrap();
    assert_eq!(queried_address, None);
}

#[test]
fn query_all_its_addresses() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let its_addresses = vec![
        (
            "ethereum".parse::<ChainName>().unwrap(),
            "0x1234567890123456789012345678901234567890"
                .parse::<Address>()
                .unwrap(),
        ),
        (
            "optimism".parse().unwrap(),
            "0x0987654321098765432109876543210987654321"
                .parse()
                .unwrap(),
        ),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();

    for (chain, address) in its_addresses.iter() {
        utils::set_its_address(deps.as_mut(), chain.clone(), address.clone()).unwrap();
    }

    let queried_addresses = utils::query_all_its_addresses(deps.as_ref()).unwrap();
    assert_eq!(queried_addresses, its_addresses);
}

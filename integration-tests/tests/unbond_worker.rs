use cosmwasm_std::StdError;
use integration_tests::contract::Contract;
use std::collections::HashSet;

pub mod test_utils;

#[test]
fn worker_should_be_in_active_workerset_of_supported_chains() {
    let (protocol, ethereum, polygon, initial_workers, _) = test_utils::setup_test_case();

    let mut chain_names_set = HashSet::new();
    chain_names_set.insert(ethereum.chain_name);
    chain_names_set.insert(polygon.chain_name);

    let query_response: Result<bool, StdError> = protocol.monitoring.query(
        &protocol.app,
        &monitoring::msg::QueryMsg::CheckWorkerIsActiveForChains {
            chain_names: chain_names_set,
            worker: initial_workers.first().unwrap().addr.clone(),
        },
    );
    assert!(query_response.is_ok());
    assert!(query_response.unwrap());
}

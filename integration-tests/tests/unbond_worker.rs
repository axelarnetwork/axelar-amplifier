use cosmwasm_std::{Addr, StdError};
use integration_tests::contract::Contract;
use std::collections::HashSet;

pub mod test_utils;

#[test]
fn worker_should_be_in_collective_active_worker_set_of_all_supported_chains() {
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

#[test]
fn worker_should_not_be_in_collective_active_worker_set_of_unsupported_chains() {
    let (protocol, _, _, initial_workers, _) = test_utils::setup_test_case();

    let mut chain_names_set = HashSet::new();
    chain_names_set.insert("Avalanche".to_string().try_into().unwrap());
    chain_names_set.insert("Osmosis".to_string().try_into().unwrap());

    let query_response: Result<bool, StdError> = protocol.monitoring.query(
        &protocol.app,
        &monitoring::msg::QueryMsg::CheckWorkerIsActiveForChains {
            chain_names: chain_names_set,
            worker: initial_workers.first().unwrap().addr.clone(),
        },
    );
    assert!(query_response.is_ok());
    assert!(!query_response.unwrap());
}

#[test]
fn worker_should_be_in_collective_active_worker_set_of_supported_and_unsupported_chains() {
    let (protocol, ethereum, polygon, initial_workers, _) = test_utils::setup_test_case();

    let mut chain_names_set = HashSet::new();
    chain_names_set.insert(ethereum.chain_name);
    chain_names_set.insert(polygon.chain_name);
    chain_names_set.insert("Avalanche".to_string().try_into().unwrap());
    chain_names_set.insert("Osmosis".to_string().try_into().unwrap());

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

#[test]
fn worker_should_not_be_in_collective_active_worker_set_of_empty_chains() {
    let (protocol, _, _, initial_workers, _) = test_utils::setup_test_case();

    let query_response: Result<bool, StdError> = protocol.monitoring.query(
        &protocol.app,
        &monitoring::msg::QueryMsg::CheckWorkerIsActiveForChains {
            chain_names: HashSet::new(),
            worker: initial_workers.first().unwrap().addr.clone(),
        },
    );
    assert!(query_response.is_ok());
    assert!(!query_response.unwrap());
}

#[test]
fn unregistered_worker_should_not_be_in_collective_active_worker_set_of_chains() {
    let (protocol, ethereum, polygon, _, _) = test_utils::setup_test_case();

    let mut chain_names_set = HashSet::new();
    chain_names_set.insert(ethereum.chain_name);
    chain_names_set.insert(polygon.chain_name);

    let query_response: Result<bool, StdError> = protocol.monitoring.query(
        &protocol.app,
        &monitoring::msg::QueryMsg::CheckWorkerIsActiveForChains {
            chain_names: chain_names_set,
            worker: Addr::unchecked("new_random_worker"),
        },
    );
    assert!(query_response.is_ok());
    assert!(!query_response.unwrap());
}

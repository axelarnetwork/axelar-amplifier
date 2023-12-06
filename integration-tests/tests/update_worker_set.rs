use connection_router::state::{CrossChainId, Message};
use cosmwasm_std::{Addr, HexBinary, Uint128};

use test_utils::{Chain, Protocol, Worker};
mod test_utils;

fn setup_test_case() -> (Protocol, Chain, Vec<Worker>) {
    let mut protocol = test_utils::setup_protocol("validators".to_string().try_into().unwrap());
    let chains: Vec<connection_router::state::ChainName> =
        vec!["Ethereum".to_string().try_into().unwrap()];

    let workers = vec![
        Worker {
            addr: Addr::unchecked("worker1"),
            supported_chains: chains.clone(),
            key_pair: test_utils::generate_key(0),
        },
        Worker {
            addr: Addr::unchecked("worker2"),
            supported_chains: chains.clone(),
            key_pair: test_utils::generate_key(1),
        },
    ];
    test_utils::register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &workers,
        protocol.service_name.clone(),
    );

    let ethereum = test_utils::setup_chain(&mut protocol, chains.get(0).unwrap().clone());
    (protocol, ethereum, workers)
}

#[test]
fn worker_set_can_be_initialized_and_then_updated() {
    let (mut protocol, ethereum, workers) = setup_test_case();
    let test_worker_set = test_utils::workers_to_worker_set(&mut protocol, &workers);

    let worker_set =
        test_utils::get_worker_set(&mut protocol.app, &ethereum.multisig_prover_address);

    assert_eq!(worker_set, test_worker_set);
}

#[test]
fn test_errors() {
    todo!()
}

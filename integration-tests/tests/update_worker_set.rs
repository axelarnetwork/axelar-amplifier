use cosmwasm_std::{Addr, Uint128};

use cw_multi_test::Executor;
use test_utils::{Chain, Protocol, Worker};

use crate::test_utils::AXL_DENOMINATION;
mod test_utils;

// Creates an instance of Axelar Amplifier with an initial workerset registered, and returns the instance, the chain, the workers, and the minimum worker bond.
fn setup_test_case(
    chains: Vec<connection_router::state::ChainName>,
) -> (Protocol, Chain, Vec<Worker>, Uint128) {
    let mut protocol = test_utils::setup_protocol("validators".to_string().try_into().unwrap());
    let min_worker_bond = Uint128::new(100);

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

    test_utils::register_service(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.governance_address.clone(),
        protocol.service_name.clone(),
        min_worker_bond.clone(),
    );

    test_utils::register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &workers,
        protocol.service_name.clone(),
        min_worker_bond.clone(),
    );

    let ethereum = test_utils::setup_chain(&mut protocol, chains.get(0).unwrap().clone());
    (protocol, ethereum, workers, min_worker_bond)
}

#[test]
fn worker_set_can_be_initialized_and_then_updated() {
    let chains: Vec<connection_router::state::ChainName> =
        vec!["Ethereum".to_string().try_into().unwrap()];
    let (mut protocol, ethereum, mut workers, min_worker_bond) = setup_test_case(chains.clone());

    let simulated_worker_set = test_utils::workers_to_worker_set(&mut protocol, &workers);

    let worker_set =
        test_utils::get_worker_set(&mut protocol.app, &ethereum.multisig_prover_address);

    assert_eq!(worker_set, simulated_worker_set);

    // add third and fourth worker
    let mut new_workers = Vec::new();
    let new_worker = Worker {
        addr: Addr::unchecked("worker3"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(2),
    };
    new_workers.push(new_worker);
    let new_worker = Worker {
        addr: Addr::unchecked("worker4"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(3),
    };
    new_workers.push(new_worker);

    test_utils::register_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.multisig_address.clone(),
        protocol.governance_address.clone(),
        protocol.genesis_address.clone(),
        &new_workers,
        protocol.service_name.clone(),
        min_worker_bond,
    );

    // remove old workers
    test_utils::deregister_workers(
        &mut protocol.app,
        protocol.service_registry_address.clone(),
        protocol.governance_address.clone(),
        &workers,
        protocol.service_name.clone(),
    );

    let response = test_utils::update_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        ethereum.multisig_prover_address.clone(),
    );

    // sign with old workers
    let session_id = test_utils::sign_proof(
        &mut protocol.app,
        &protocol.multisig_address,
        &workers,
        response,
    );

    let proof = test_utils::get_proof(
        &mut protocol.app,
        &ethereum.multisig_prover_address,
        &session_id,
    );
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));

    assert_eq!(proof.message_ids.len(), 0);

    let simulated_new_worker_set = test_utils::workers_to_worker_set(&mut protocol, &new_workers);

    let (poll_id, expiry) = test_utils::create_worker_set_poll(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        ethereum.voting_verifier_address.clone(),
        simulated_new_worker_set,
    );

    // do voting
    test_utils::vote_true_for_all(
        &mut protocol.app,
        &ethereum.voting_verifier_address,
        &vec![true; 1],
        &new_workers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(
        &mut protocol.app,
        &ethereum.voting_verifier_address,
        poll_id,
    );

    test_utils::confirm_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        ethereum.multisig_prover_address.clone(),
    );
}

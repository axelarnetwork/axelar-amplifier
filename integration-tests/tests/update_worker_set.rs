use cosmwasm_std::Addr;
use cw_multi_test::Executor;

use integration_tests::contract::Contract;
use multisig_prover::msg::ExecuteMsg;
use test_utils::Worker;

use crate::test_utils::get_multisig_session_id;

pub mod test_utils;

#[test]
fn worker_set_can_be_initialized_and_then_manually_updated() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        workers: initial_workers,
        min_worker_bond,
        ..
    } = test_utils::setup_test_case();

    let simulated_worker_set = test_utils::workers_to_worker_set(&mut protocol, &initial_workers);

    let worker_set =
        test_utils::get_worker_set_from_prover(&mut protocol.app, &ethereum.multisig_prover);

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

    let expected_new_worker_set = test_utils::workers_to_worker_set(&mut protocol, &new_workers);

    test_utils::register_workers(&mut protocol, &new_workers, min_worker_bond);

    // remove old workers
    test_utils::deregister_workers(&mut protocol, &initial_workers);

    let response = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet,
            &[],
        )
        .unwrap();

    // sign with old workers
    let session_id = test_utils::sign_proof(&mut protocol, &initial_workers, response);

    let proof = test_utils::get_proof(&mut protocol.app, &ethereum.multisig_prover, &session_id);
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));

    assert_eq!(proof.message_ids.len(), 0);

    let (poll_id, expiry) = test_utils::create_worker_set_poll(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        &ethereum.voting_verifier,
        expected_new_worker_set.clone(),
    );

    // do voting
    test_utils::vote_true_for_worker_set(
        &mut protocol.app,
        &ethereum.voting_verifier,
        &new_workers,
        poll_id,
    );

    test_utils::advance_at_least_to_height(&mut protocol.app, expiry);

    test_utils::end_poll(&mut protocol.app, &ethereum.voting_verifier, poll_id);

    test_utils::confirm_worker_set(
        &mut protocol.app,
        Addr::unchecked("relayer"),
        &ethereum.multisig_prover,
    );

    let new_worker_set =
        test_utils::get_worker_set_from_prover(&mut protocol.app, &ethereum.multisig_prover);
    assert_eq!(new_worker_set, expected_new_worker_set);

    let coordinator_worker_set = test_utils::get_worker_set_from_coordinator(
        &mut protocol.app,
        &protocol.coordinator,
        ethereum.chain_name,
    );
    assert_eq!(coordinator_worker_set, expected_new_worker_set);
}

#[test]
fn worker_set_cannot_be_updated_again_while_pending_worker_is_not_yet_confirmed() {
    let chains = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];
    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        workers: initial_workers,
        min_worker_bond,
        ..
    } = test_utils::setup_test_case();

    let simulated_worker_set = test_utils::workers_to_worker_set(&mut protocol, &initial_workers);

    let worker_set =
        test_utils::get_worker_set_from_prover(&mut protocol.app, &ethereum.multisig_prover);

    assert_eq!(worker_set, simulated_worker_set);

    // creating a new worker set that only consists of two new workers
    let first_wave_of_new_workers = test_utils::create_new_workers_vec(
        chains.clone(),
        vec![("worker3".to_string(), 2), ("worker4".to_string(), 3)],
    );

    let expected_new_worker_set =
        test_utils::workers_to_worker_set(&mut protocol, &first_wave_of_new_workers);

    test_utils::register_workers(&mut protocol, &first_wave_of_new_workers, min_worker_bond);

    // Deregister old workers
    test_utils::deregister_workers(&mut protocol, &initial_workers);

    let response = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet,
            &[],
        )
        .unwrap();

    let session_id = test_utils::sign_proof(&mut protocol, &initial_workers, response);

    let proof = test_utils::get_proof(&mut protocol.app, &ethereum.multisig_prover, &session_id);

    // proof must be completed
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));
    assert_eq!(proof.message_ids.len(), 0);

    // starting and ending a poll for the first worker set rotation
    test_utils::execute_worker_set_poll(
        &mut protocol,
        &Addr::unchecked("relayer"),
        &ethereum.voting_verifier,
        &first_wave_of_new_workers,
    );

    // try to rotate again. this should be ignored, because the first rotation is not yet confirmed
    let second_wave_of_new_workers =
        test_utils::create_new_workers_vec(chains.clone(), vec![("worker5".to_string(), 5)]);

    test_utils::register_workers(&mut protocol, &second_wave_of_new_workers, min_worker_bond);

    // Deregister old workers
    test_utils::deregister_workers(&mut protocol, &first_wave_of_new_workers);

    // call update_worker_set again. This should just trigger resigning for the initial worker set update,
    // ignoring any further changes to the worker set
    let response = ethereum.multisig_prover.execute(
        &mut protocol.app,
        ethereum.multisig_prover.admin_addr.clone(),
        &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet,
    );
    assert!(response.is_ok());

    test_utils::confirm_worker_set(
        &mut protocol.app,
        ethereum.multisig_prover.admin_addr.clone(),
        &ethereum.multisig_prover,
    );

    let new_worker_set =
        test_utils::get_worker_set_from_prover(&mut protocol.app, &ethereum.multisig_prover);

    assert_eq!(new_worker_set, expected_new_worker_set);

    // starting and ending a poll for the second worker rotation
    // in reality, this shouldn't succeed, because the prover should have prevented another rotation while an existing rotation was in progress.
    // But even if there is a poll, the prover should ignore it
    test_utils::execute_worker_set_poll(
        &mut protocol,
        &Addr::unchecked("relayer"),
        &ethereum.voting_verifier,
        &second_wave_of_new_workers,
    );

    let response = ethereum.multisig_prover.execute(
        &mut protocol.app,
        ethereum.multisig_prover.admin_addr.clone(),
        &multisig_prover::msg::ExecuteMsg::ConfirmVerifierSet,
    );
    assert!(response.is_err());
}

#[test]
fn worker_set_update_can_be_resigned() {
    let chains = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];
    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        workers: initial_workers,
        min_worker_bond,
        ..
    } = test_utils::setup_test_case();

    let simulated_worker_set = test_utils::workers_to_worker_set(&mut protocol, &initial_workers);

    let worker_set =
        test_utils::get_worker_set_from_prover(&mut protocol.app, &ethereum.multisig_prover);

    assert_eq!(worker_set, simulated_worker_set);

    // creating a new worker set that only consists of two new workers
    let first_wave_of_new_workers = test_utils::create_new_workers_vec(
        chains.clone(),
        vec![("worker3".to_string(), 2), ("worker4".to_string(), 3)],
    );

    test_utils::register_workers(&mut protocol, &first_wave_of_new_workers, min_worker_bond);

    // Deregister old workers
    test_utils::deregister_workers(&mut protocol, &initial_workers);

    let response = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet,
            &[],
        )
        .unwrap();

    let first_session_id = get_multisig_session_id(response.clone());

    // signing didn't occur, trigger signing again
    let response = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet,
            &[],
        )
        .unwrap();

    let second_session_id = get_multisig_session_id(response.clone());
    assert_ne!(first_session_id, second_session_id);

    test_utils::sign_proof(&mut protocol, &initial_workers, response);

    // signing did occur, trigger signing again (in case proof was lost)
    let response = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet,
            &[],
        )
        .unwrap();

    let third_session_id = get_multisig_session_id(response.clone());
    assert_ne!(first_session_id, second_session_id);
    assert_ne!(second_session_id, third_session_id);

    test_utils::sign_proof(&mut protocol, &initial_workers, response);

    let proof = test_utils::get_proof(
        &mut protocol.app,
        &ethereum.multisig_prover,
        &second_session_id,
    );

    // proof must be completed
    assert!(matches!(
        proof.status,
        multisig_prover::msg::ProofStatus::Completed { .. }
    ));
}

#[test]
fn governance_should_confirm_new_worker_set_without_verification() {
    let chains: Vec<router_api::ChainName> = vec!["Ethereum".to_string().try_into().unwrap()];
    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        workers: initial_workers,
        min_worker_bond,
        ..
    } = test_utils::setup_test_case();

    // add third worker
    let mut new_workers = Vec::new();
    let new_worker = Worker {
        addr: Addr::unchecked("worker3"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(2),
    };
    new_workers.push(new_worker);

    let expected_new_worker_set = test_utils::workers_to_worker_set(&mut protocol, &new_workers);

    test_utils::register_workers(&mut protocol, &new_workers, min_worker_bond);

    test_utils::deregister_workers(&mut protocol, &initial_workers);

    let _ = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &ExecuteMsg::UpdateVerifierSet,
            &[],
        )
        .unwrap();

    test_utils::confirm_worker_set(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &ethereum.multisig_prover,
    );

    let new_worker_set =
        test_utils::get_worker_set_from_prover(&mut protocol.app, &ethereum.multisig_prover);

    assert_eq!(new_worker_set, expected_new_worker_set);
}

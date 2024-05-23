use cosmwasm_std::Addr;
use cw_multi_test::Executor;

use integration_tests::contract::Contract;
use multisig_prover::msg::ExecuteMsg;
use test_utils::Verifier;

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
        verifiers: initial_verifiers,
        min_verifier_bond,
        ..
    } = test_utils::setup_test_case();

    let simulated_worker_set =
        test_utils::verifiers_to_worker_set(&mut protocol, &initial_verifiers);

    let worker_set =
        test_utils::get_worker_set_from_prover(&mut protocol.app, &ethereum.multisig_prover);

    assert_eq!(worker_set, simulated_worker_set);

    // add third and fourth verifier
    let mut new_verifiers = Vec::new();
    let new_verifier = Verifier {
        addr: Addr::unchecked("verifier3"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(2),
    };
    new_verifiers.push(new_verifier);
    let new_verifier = Verifier {
        addr: Addr::unchecked("verifier4"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(3),
    };
    new_verifiers.push(new_verifier);

    let expected_new_worker_set =
        test_utils::verifiers_to_worker_set(&mut protocol, &new_verifiers);

    test_utils::register_verifiers(&mut protocol, &new_verifiers, min_verifier_bond);

    // remove old verifiers
    test_utils::deregister_verifiers(&mut protocol, &initial_verifiers);

    let response = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
            &[],
        )
        .unwrap();

    // sign with old verifiers
    let session_id = test_utils::sign_proof(&mut protocol, &initial_verifiers, response);

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
        &new_verifiers,
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
fn worker_set_cannot_be_updated_again_while_pending_verifier_is_not_yet_confirmed() {
    let chains = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];
    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        verifiers: initial_verifiers,
        min_verifier_bond,
        ..
    } = test_utils::setup_test_case();

    let simulated_worker_set =
        test_utils::verifiers_to_worker_set(&mut protocol, &initial_verifiers);

    let worker_set =
        test_utils::get_worker_set_from_prover(&mut protocol.app, &ethereum.multisig_prover);

    assert_eq!(worker_set, simulated_worker_set);

    // creating a new worker set that only consists of two new verifiers
    let first_wave_of_new_verifiers = test_utils::create_new_verifiers_vec(
        chains.clone(),
        vec![("verifier3".to_string(), 2), ("verifier4".to_string(), 3)],
    );

    let expected_new_worker_set =
        test_utils::verifiers_to_worker_set(&mut protocol, &first_wave_of_new_verifiers);

    test_utils::register_verifiers(
        &mut protocol,
        &first_wave_of_new_verifiers,
        min_verifier_bond,
    );

    // Deregister old verifiers
    test_utils::deregister_verifiers(&mut protocol, &initial_verifiers);

    let response = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
            &[],
        )
        .unwrap();

    let session_id = test_utils::sign_proof(&mut protocol, &initial_verifiers, response);

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
        &first_wave_of_new_verifiers,
    );

    // try to rotate again. this should be ignored, because the first rotation is not yet confirmed
    let second_wave_of_new_verifiers =
        test_utils::create_new_verifiers_vec(chains.clone(), vec![("verifier5".to_string(), 5)]);

    test_utils::register_verifiers(
        &mut protocol,
        &second_wave_of_new_verifiers,
        min_verifier_bond,
    );

    // Deregister old verifiers
    test_utils::deregister_verifiers(&mut protocol, &first_wave_of_new_verifiers);

    // call update_worker_set again. This should just trigger resigning for the initial worker set update,
    // ignoring any further changes to the worker set
    let response = ethereum.multisig_prover.execute(
        &mut protocol.app,
        ethereum.multisig_prover.admin_addr.clone(),
        &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
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

    // starting and ending a poll for the second verifier rotation
    // in reality, this shouldn't succeed, because the prover should have prevented another rotation while an existing rotation was in progress.
    // But even if there is a poll, the prover should ignore it
    test_utils::execute_worker_set_poll(
        &mut protocol,
        &Addr::unchecked("relayer"),
        &ethereum.voting_verifier,
        &second_wave_of_new_verifiers,
    );

    let response = ethereum.multisig_prover.execute(
        &mut protocol.app,
        ethereum.multisig_prover.admin_addr.clone(),
        &multisig_prover::msg::ExecuteMsg::ConfirmWorkerSet,
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
        verifiers: initial_verifiers,
        min_verifier_bond,
        ..
    } = test_utils::setup_test_case();

    let simulated_worker_set =
        test_utils::verifiers_to_worker_set(&mut protocol, &initial_verifiers);

    let worker_set =
        test_utils::get_worker_set_from_prover(&mut protocol.app, &ethereum.multisig_prover);

    assert_eq!(worker_set, simulated_worker_set);

    // creating a new worker set that only consists of two new verifiers
    let first_wave_of_new_verifiers = test_utils::create_new_verifiers_vec(
        chains.clone(),
        vec![("verifier3".to_string(), 2), ("verifier4".to_string(), 3)],
    );

    test_utils::register_verifiers(
        &mut protocol,
        &first_wave_of_new_verifiers,
        min_verifier_bond,
    );

    // Deregister old verifiers
    test_utils::deregister_verifiers(&mut protocol, &initial_verifiers);

    let response = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
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
            &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
            &[],
        )
        .unwrap();

    let second_session_id = get_multisig_session_id(response.clone());
    assert_ne!(first_session_id, second_session_id);

    test_utils::sign_proof(&mut protocol, &initial_verifiers, response);

    // signing did occur, trigger signing again (in case proof was lost)
    let response = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
            &[],
        )
        .unwrap();

    let third_session_id = get_multisig_session_id(response.clone());
    assert_ne!(first_session_id, second_session_id);
    assert_ne!(second_session_id, third_session_id);

    test_utils::sign_proof(&mut protocol, &initial_verifiers, response);

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
        verifiers: initial_verifiers,
        min_verifier_bond,
        ..
    } = test_utils::setup_test_case();

    // add third verifier
    let mut new_verifiers = Vec::new();
    let new_verifier = Verifier {
        addr: Addr::unchecked("verifier3"),
        supported_chains: chains.clone(),
        key_pair: test_utils::generate_key(2),
    };
    new_verifiers.push(new_verifier);

    let expected_new_worker_set =
        test_utils::verifiers_to_worker_set(&mut protocol, &new_verifiers);

    test_utils::register_verifiers(&mut protocol, &new_verifiers, min_verifier_bond);

    test_utils::deregister_verifiers(&mut protocol, &initial_verifiers);

    let _ = protocol
        .app
        .execute_contract(
            ethereum.multisig_prover.admin_addr.clone(),
            ethereum.multisig_prover.contract_addr.clone(),
            &ExecuteMsg::UpdateWorkerSet,
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

use cosmwasm_std::BlockInfo;
use integration_tests::contract::Contract;
use service_registry::msg::ExecuteMsg;

pub mod test_utils;

#[test]
fn claim_stake_after_rotation_success() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".try_into().unwrap(),
        "Polygon".try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        chain2: polygon,
        verifiers,
        min_verifier_bond,
        unbonding_period_days,
        ..
    } = test_utils::setup_test_case();

    let before_balances = test_utils::query_balances(&protocol.app, &verifiers);

    let new_verifiers = test_utils::create_new_verifiers_vec(
        chains.clone(),
        vec![("verifier3".to_string(), 3), ("verifier4".to_string(), 4)],
    );

    test_utils::register_verifiers(&mut protocol, &new_verifiers, min_verifier_bond);

    test_utils::deregister_verifiers(&mut protocol, &verifiers);

    test_utils::rotate_active_verifier_set(&mut protocol, ethereum, &verifiers, &new_verifiers);
    test_utils::rotate_active_verifier_set(&mut protocol, polygon, &verifiers, &new_verifiers);

    for verifier in &verifiers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            verifier.addr.clone(),
            &ExecuteMsg::UnbondVerifier {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    // balances don't change after deregistering
    assert_eq!(
        before_balances,
        test_utils::query_balances(&protocol.app, &verifiers)
    );

    let block = protocol.app.block_info();
    protocol.app.set_block(BlockInfo {
        height: block.height + 1,
        time: protocol
            .app
            .block_info()
            .time
            .plus_days(unbonding_period_days.into()),
        ..block
    });

    let claim_results = test_utils::claim_stakes(&mut protocol, &verifiers);
    for claim_result in claim_results {
        assert!(claim_result.is_ok());
    }

    let after_balances = test_utils::query_balances(&protocol.app, &verifiers);

    for (before_balance, after_balance) in before_balances.into_iter().zip(after_balances) {
        assert_eq!(
            after_balance,
            before_balance + min_verifier_bond.into_inner()
        );
    }
}

#[test]
fn claim_stake_when_in_all_active_verifier_sets_fails() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".try_into().unwrap(),
        "Polygon".try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        verifiers,
        min_verifier_bond,
        ..
    } = test_utils::setup_test_case();

    let new_verifiers = test_utils::create_new_verifiers_vec(
        chains.clone(),
        vec![("verifier3".to_string(), 3), ("verifier4".to_string(), 4)],
    );

    test_utils::register_verifiers(&mut protocol, &new_verifiers, min_verifier_bond);

    test_utils::deregister_verifiers(&mut protocol, &verifiers);

    for verifier in &verifiers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            verifier.addr.clone(),
            &ExecuteMsg::UnbondVerifier {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    let claim_results = test_utils::claim_stakes(&mut protocol, &verifiers);
    for claim_result in claim_results {
        assert!(claim_result.is_err());
    }
}

#[test]
fn claim_stake_when_in_some_active_verifier_sets_fails() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".try_into().unwrap(),
        "Polygon".try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        verifiers,
        min_verifier_bond,
        ..
    } = test_utils::setup_test_case();

    let new_verifiers = test_utils::create_new_verifiers_vec(
        chains.clone(),
        vec![("verifier3".to_string(), 3), ("verifier4".to_string(), 4)],
    );

    test_utils::register_verifiers(&mut protocol, &new_verifiers, min_verifier_bond);

    test_utils::deregister_verifiers(&mut protocol, &verifiers);

    // Only rotate the first chain's verifier set
    test_utils::rotate_active_verifier_set(&mut protocol, ethereum, &verifiers, &new_verifiers);

    for verifier in &verifiers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            verifier.addr.clone(),
            &ExecuteMsg::UnbondVerifier {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    let claim_results = test_utils::claim_stakes(&mut protocol, &verifiers);
    for claim_result in claim_results {
        assert!(claim_result.is_err());
    }
}

#[test]
fn claim_stake_after_deregistering_before_rotation_fails() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".try_into().unwrap(),
        "Polygon".try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        verifiers,
        min_verifier_bond,
        ..
    } = test_utils::setup_test_case();

    let new_verifiers = test_utils::create_new_verifiers_vec(
        chains.clone(),
        vec![("verifier3".to_string(), 3), ("verifier4".to_string(), 4)],
    );

    test_utils::register_verifiers(&mut protocol, &new_verifiers, min_verifier_bond);

    for verifier in &verifiers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            verifier.addr.clone(),
            &ExecuteMsg::DeregisterChainSupport {
                service_name: protocol.service_name.to_string(),
                chains: chains.clone(),
            },
        );
        assert!(response.is_ok());
    }

    for verifier in &verifiers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            verifier.addr.clone(),
            &ExecuteMsg::UnbondVerifier {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    let claim_results = test_utils::claim_stakes(&mut protocol, &verifiers);
    for claim_result in claim_results {
        assert!(claim_result.is_err());
    }
}

#[test]
fn claim_stake_when_jailed_fails() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".try_into().unwrap(),
        "Polygon".try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        chain2: polygon,
        verifiers,
        min_verifier_bond,
        ..
    } = test_utils::setup_test_case();

    let new_verifiers = test_utils::create_new_verifiers_vec(
        chains.clone(),
        vec![("verifier3".to_string(), 3), ("verifier4".to_string(), 4)],
    );

    test_utils::register_verifiers(&mut protocol, &new_verifiers, min_verifier_bond);

    test_utils::deregister_verifiers(&mut protocol, &verifiers);

    test_utils::rotate_active_verifier_set(&mut protocol, ethereum, &verifiers, &new_verifiers);
    test_utils::rotate_active_verifier_set(&mut protocol, polygon, &verifiers, &new_verifiers);

    for verifier in &verifiers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            verifier.addr.clone(),
            &ExecuteMsg::UnbondVerifier {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    let response = protocol.service_registry.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &ExecuteMsg::JailVerifiers {
            service_name: protocol.service_name.to_string(),
            verifiers: vec!["verifier1".to_string(), "verifier2".to_string()],
        },
    );
    assert!(response.is_ok());

    let claim_results = test_utils::claim_stakes(&mut protocol, &verifiers);
    for claim_result in claim_results {
        assert!(claim_result.clone().is_err());
    }
}

#[test]
fn claim_stake_when_in_next_verifier_sets_fails() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".try_into().unwrap(),
        "Polygon".try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        chain2: polygon,
        verifiers,
        min_verifier_bond,
        ..
    } = test_utils::setup_test_case();

    let new_verifiers = test_utils::create_new_verifiers_vec(
        chains.clone(),
        vec![("verifier3".to_string(), 3), ("verifier4".to_string(), 4)],
    );

    test_utils::register_verifiers(&mut protocol, &new_verifiers, min_verifier_bond);

    test_utils::deregister_verifiers(&mut protocol, &verifiers);

    let response = ethereum.multisig_prover.execute(
        &mut protocol.app,
        ethereum.multisig_prover.admin_addr.clone(),
        &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet,
    );
    assert!(response.is_ok());

    let response = polygon.multisig_prover.execute(
        &mut protocol.app,
        polygon.multisig_prover.admin_addr.clone(),
        &multisig_prover::msg::ExecuteMsg::UpdateVerifierSet,
    );
    assert!(response.is_ok());

    for verifier in &verifiers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            verifier.addr.clone(),
            &ExecuteMsg::UnbondVerifier {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    let claim_results = test_utils::claim_stakes(&mut protocol, &verifiers);
    for claim_result in claim_results {
        assert!(claim_result.is_err());
    }
}

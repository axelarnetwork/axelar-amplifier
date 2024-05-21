use cosmwasm_std::BlockInfo;
use integration_tests::contract::Contract;
use service_registry::msg::ExecuteMsg;

pub mod test_utils;

#[test]
fn claim_stake_after_rotation_success() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        chain2: polygon,
        workers,
        min_worker_bond,
        unbonding_period_days,
        ..
    } = test_utils::setup_test_case();

    let before_balances = test_utils::query_balances(&protocol.app, &workers);

    let new_workers = test_utils::create_new_workers_vec(
        chains.clone(),
        vec![("worker3".to_string(), 3), ("worker4".to_string(), 4)],
    );

    test_utils::register_workers(&mut protocol, &new_workers, min_worker_bond);

    test_utils::deregister_workers(&mut protocol, &workers);

    test_utils::rotate_active_worker_set(&mut protocol, ethereum, &workers, &new_workers);
    test_utils::rotate_active_worker_set(&mut protocol, polygon, &workers, &new_workers);

    for worker in &workers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &ExecuteMsg::UnbondWorker {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    // balances don't change after deregistering
    assert_eq!(
        before_balances,
        test_utils::query_balances(&protocol.app, &workers)
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

    let claim_results = test_utils::claim_stakes(&mut protocol, &workers);
    for claim_result in claim_results {
        assert!(claim_result.is_ok());
    }

    let after_balances = test_utils::query_balances(&protocol.app, &workers);

    for (before_balance, after_balance) in before_balances.into_iter().zip(after_balances) {
        assert_eq!(after_balance, before_balance + min_worker_bond);
    }
}

#[test]
fn claim_stake_when_in_all_active_worker_sets_fails() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        workers,
        min_worker_bond,
        ..
    } = test_utils::setup_test_case();

    let new_workers = test_utils::create_new_workers_vec(
        chains.clone(),
        vec![("worker3".to_string(), 3), ("worker4".to_string(), 4)],
    );

    test_utils::register_workers(&mut protocol, &new_workers, min_worker_bond);

    test_utils::deregister_workers(&mut protocol, &workers);

    for worker in &workers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &ExecuteMsg::UnbondWorker {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    let claim_results = test_utils::claim_stakes(&mut protocol, &workers);
    for claim_result in claim_results {
        assert!(claim_result.is_err());
    }
}

#[test]
fn claim_stake_when_in_some_active_worker_sets_fails() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        workers,
        min_worker_bond,
        ..
    } = test_utils::setup_test_case();

    let new_workers = test_utils::create_new_workers_vec(
        chains.clone(),
        vec![("worker3".to_string(), 3), ("worker4".to_string(), 4)],
    );

    test_utils::register_workers(&mut protocol, &new_workers, min_worker_bond);

    test_utils::deregister_workers(&mut protocol, &workers);

    // Only rotate the first chain's workerset
    test_utils::rotate_active_worker_set(&mut protocol, ethereum, &workers, &new_workers);

    for worker in &workers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &ExecuteMsg::UnbondWorker {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    let claim_results = test_utils::claim_stakes(&mut protocol, &workers);
    for claim_result in claim_results {
        assert!(claim_result.is_err());
    }
}

#[test]
fn claim_stake_after_deregistering_before_rotation_fails() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        workers,
        min_worker_bond,
        ..
    } = test_utils::setup_test_case();

    let new_workers = test_utils::create_new_workers_vec(
        chains.clone(),
        vec![("worker3".to_string(), 3), ("worker4".to_string(), 4)],
    );

    test_utils::register_workers(&mut protocol, &new_workers, min_worker_bond);

    for worker in &workers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &ExecuteMsg::DeregisterChainSupport {
                service_name: protocol.service_name.to_string(),
                chains: chains.clone(),
            },
        );
        assert!(response.is_ok());
    }

    for worker in &workers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &ExecuteMsg::UnbondWorker {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    let claim_results = test_utils::claim_stakes(&mut protocol, &workers);
    for claim_result in claim_results {
        assert!(claim_result.is_err());
    }
}

#[test]
fn claim_stake_when_jailed_fails() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        chain2: polygon,
        workers,
        min_worker_bond,
        ..
    } = test_utils::setup_test_case();

    let new_workers = test_utils::create_new_workers_vec(
        chains.clone(),
        vec![("worker3".to_string(), 3), ("worker4".to_string(), 4)],
    );

    test_utils::register_workers(&mut protocol, &new_workers, min_worker_bond);

    test_utils::deregister_workers(&mut protocol, &workers);

    test_utils::rotate_active_worker_set(&mut protocol, ethereum, &workers, &new_workers);
    test_utils::rotate_active_worker_set(&mut protocol, polygon, &workers, &new_workers);

    for worker in &workers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &ExecuteMsg::UnbondWorker {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    let response = protocol.service_registry.execute(
        &mut protocol.app,
        protocol.governance_address.clone(),
        &ExecuteMsg::JailWorkers {
            service_name: protocol.service_name.to_string(),
            workers: vec!["worker1".to_string(), "worker2".to_string()],
        },
    );
    assert!(response.is_ok());

    let claim_results = test_utils::claim_stakes(&mut protocol, &workers);
    for claim_result in claim_results {
        assert!(claim_result.clone().is_err());
    }
}

#[test]
fn claim_stake_when_in_next_worker_sets_fails() {
    let chains: Vec<router_api::ChainName> = vec![
        "Ethereum".to_string().try_into().unwrap(),
        "Polygon".to_string().try_into().unwrap(),
    ];

    let test_utils::TestCase {
        mut protocol,
        chain1: ethereum,
        chain2: polygon,
        workers,
        min_worker_bond,
        ..
    } = test_utils::setup_test_case();

    let new_workers = test_utils::create_new_workers_vec(
        chains.clone(),
        vec![("worker3".to_string(), 3), ("worker4".to_string(), 4)],
    );

    test_utils::register_workers(&mut protocol, &new_workers, min_worker_bond);

    test_utils::deregister_workers(&mut protocol, &workers);

    let response = ethereum.multisig_prover.execute(
        &mut protocol.app,
        ethereum.multisig_prover.admin_addr.clone(),
        &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
    );
    assert!(response.is_ok());

    let response = polygon.multisig_prover.execute(
        &mut protocol.app,
        polygon.multisig_prover.admin_addr.clone(),
        &multisig_prover::msg::ExecuteMsg::UpdateWorkerSet,
    );
    assert!(response.is_ok());

    for worker in &workers {
        let response = protocol.service_registry.execute(
            &mut protocol.app,
            worker.addr.clone(),
            &ExecuteMsg::UnbondWorker {
                service_name: protocol.service_name.to_string(),
            },
        );
        assert!(response.is_ok());
    }

    let claim_results = test_utils::claim_stakes(&mut protocol, &workers);
    for claim_result in claim_results {
        assert!(claim_result.is_err());
    }
}

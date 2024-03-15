mod test_utils;

use std::{str::FromStr, vec};

use connection_router_api::ChainName;
use cosmwasm_std::{coins, Addr, BlockInfo, StdResult, Uint128};
use cw_multi_test::App;
use integration_tests::contract::Contract;
use service_registry::msg::QueryMsg;
use service_registry::state::{WeightedWorker, WORKER_WEIGHT};
use service_registry::{
    msg::ExecuteMsg,
    state::{AuthorizationState, BondingState, Worker},
    ContractError,
};

const AXL_DENOMINATION: &str = "uaxl";

#[test]
fn register_service() {
    let mut app = App::default();
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: "validators".into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond: Uint128::zero(),
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let err = service_registry
        .execute(
            &mut app,
            Addr::unchecked("some other account"),
            &ExecuteMsg::RegisterService {
                service_name: "validators".into(),
                service_contract: Addr::unchecked("nowhere"),
                min_num_workers: 0,
                max_num_workers: Some(100),
                min_worker_bond: Uint128::zero(),
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        )
        .unwrap_err();
    test_utils::are_contract_err_strings_equal(err, ContractError::Unauthorized);
}

#[test]
fn authorize_worker() {
    let mut app = App::default();
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond: Uint128::zero(),
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance,
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![Addr::unchecked("worker").into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let err = service_registry
        .execute(
            &mut app,
            Addr::unchecked("some other address"),
            &ExecuteMsg::AuthorizeWorkers {
                workers: vec![Addr::unchecked("worker").into()],
                service_name: service_name.into(),
            },
        )
        .unwrap_err();
    test_utils::are_contract_err_strings_equal(err, ContractError::Unauthorized);
}

#[test]
fn bond_worker() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance,
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker,
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());
}

#[test]
fn register_chain_support() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance,
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(
        workers,
        vec![WeightedWorker {
            worker_info: Worker {
                address: worker,
                bonding_state: BondingState::Bonded {
                    amount: min_worker_bond
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: service_name.into()
            },
            weight: WORKER_WEIGHT
        }]
    );

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name: ChainName::from_str("random chain").unwrap(),
            },
        )
        .unwrap();
    assert_eq!(workers, vec![]);
}

/// If a bonded and authorized worker deregisters support for a chain they previously registered support for,
/// that worker should no longer be part of the active worker set for that chain
#[test]
fn register_and_deregister_support_for_single_chain() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    // Deregister chain support
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::DeregisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![]);
}

/// Same setting and goal as register_and_deregister_support_for_single_chain() but for multiple chains.
#[test]
fn register_and_deregister_support_for_multiple_chains() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chains = vec![
        ChainName::from_str("ethereum").unwrap(),
        ChainName::from_str("binance").unwrap(),
        ChainName::from_str("avalanche").unwrap(),
    ];

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: chains.clone(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::DeregisterChainSupport {
            service_name: service_name.into(),
            chains: chains.clone(),
        },
    );
    assert!(res.is_ok());

    for chain in chains {
        let workers: Vec<WeightedWorker> = service_registry
            .query(
                &app,
                &QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name: chain,
                },
            )
            .unwrap();
        assert_eq!(workers, vec![]);
    }
}

/// If a bonded and authorized worker deregisters support for the first chain among multiple chains,
/// they should remain part of the active worker set for all chains except the first one.
#[test]
fn register_for_multiple_chains_deregister_for_first_one() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chains = vec![
        ChainName::from_str("ethereum").unwrap(),
        ChainName::from_str("binance").unwrap(),
        ChainName::from_str("avalanche").unwrap(),
    ];

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: chains.clone(),
        },
    );
    assert!(res.is_ok());

    // Deregister only the first chain
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::DeregisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chains[0].clone()],
        },
    );
    assert!(res.is_ok());

    // Verify that worker is not associated with the deregistered chain
    let deregistered_chain = chains[0].clone();
    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name: deregistered_chain,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![]);

    // Verify that worker is still associated with other chains
    for chain in chains.iter().skip(1) {
        let workers: Vec<WeightedWorker> = service_registry
            .query(
                &app,
                &QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name: chain.clone(),
                },
            )
            .unwrap();
        assert_eq!(
            workers,
            vec![WeightedWorker {
                worker_info: Worker {
                    address: worker.clone(),
                    bonding_state: BondingState::Bonded {
                        amount: min_worker_bond
                    },
                    authorization_state: AuthorizationState::Authorized,
                    service_name: service_name.into()
                },
                weight: WORKER_WEIGHT
            }]
        );
    }
}

/// If a bonded and authorized worker registers support for one chain and later deregisters support for another chain,
/// the active worker set for the original chain should remain unaffected by the deregistration.
#[test]
fn register_support_for_a_chain_deregister_support_for_another_chain() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let second_chain_name = ChainName::from_str("avalanche").unwrap();
    // Deregister support for another chain
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::DeregisterChainSupport {
            service_name: service_name.into(),
            chains: vec![second_chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(
        workers,
        vec![WeightedWorker {
            worker_info: Worker {
                address: worker,
                bonding_state: BondingState::Bonded {
                    amount: min_worker_bond
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: service_name.into()
            },
            weight: WORKER_WEIGHT
        }]
    );
}

/// If a bonded and authorized worker registers, deregisters, and again registers their support for a single chain,
/// the active worker set of that chain should include the worker.
#[test]
fn register_deregister_register_support_for_single_chain() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::DeregisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    // Second support declaration
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(
        workers,
        vec![WeightedWorker {
            worker_info: Worker {
                address: worker,
                bonding_state: BondingState::Bonded {
                    amount: min_worker_bond
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: service_name.into()
            },
            weight: WORKER_WEIGHT
        }]
    );
}

/// If a bonded and authorized worker deregisters their support for a chain they have not previously registered
/// support for, the call should be ignored and the active worker set of the chain should be intact.
#[test]
fn deregister_previously_unsupported_single_chain() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::DeregisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![])
}

/// If an unbonded but authorized worker deregisters support for a chain they previously registered support for,
/// that worker should not be part of the active worker set for that chain.
#[test]
fn register_and_deregister_support_for_single_chain_unbonded() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::DeregisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![]);
}

/// If a worker that is not part of a service deregisters support for a chain from that specific service,
/// process should return a contract error of type WorkerNotFound.
#[test]
fn deregister_from_unregistered_worker_single_chain() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let err = service_registry
        .execute(
            &mut app,
            worker.clone(),
            &ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap_err();

    test_utils::are_contract_err_strings_equal(err, ContractError::WorkerNotFound);

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![]);
}

/// If a worker deregisters support for a chain of an unregistered service,
/// process should return a contract error of type ServiceNotFound.
#[test]
fn deregister_single_chain_for_nonexistent_service() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let chain_name = ChainName::from_str("ethereum").unwrap();
    let err = service_registry
        .execute(
            &mut app,
            worker.clone(),
            &ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap_err();

    test_utils::are_contract_err_strings_equal(err, ContractError::ServiceNotFound);
}

#[test]
fn unbond_worker() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance,
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::UnbondWorker {
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![])
}

#[test]
fn bond_wrong_denom() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, "funnydenom"))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let err = service_registry
        .execute_with_funds(
            &mut app,
            worker.clone(),
            &ExecuteMsg::BondWorker {
                service_name: service_name.into(),
            },
            &coins(min_worker_bond.u128(), "funnydenom"),
        )
        .unwrap_err();

    test_utils::are_contract_err_strings_equal(err, ContractError::WrongDenom);
}

#[test]
fn bond_but_not_authorized() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![])
}

#[test]
fn bond_but_not_enough() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance,
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128() / 2, AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![])
}

#[test]
fn bond_before_authorize() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance,
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(
        workers,
        vec![WeightedWorker {
            worker_info: Worker {
                address: worker,
                bonding_state: BondingState::Bonded {
                    amount: min_worker_bond
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: service_name.into()
            },
            weight: WORKER_WEIGHT
        }]
    );
}

#[test]
fn unbond_then_rebond() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance,
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::UnbondWorker {
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let workers: Vec<WeightedWorker> = service_registry
        .query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(
        workers,
        vec![WeightedWorker {
            worker_info: Worker {
                address: worker,
                bonding_state: BondingState::Bonded {
                    amount: min_worker_bond
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: service_name.into()
            },
            weight: WORKER_WEIGHT
        }]
    );
}

#[test]
fn unbonding_period() {
    let worker = Addr::unchecked("worker");
    let min_worker_bond = Uint128::new(100);
    let initial_bal = min_worker_bond.u128() * 2;
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(initial_bal, AXL_DENOMINATION))
            .unwrap()
    });
    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let unbonding_period_days = 1;
    let res = service_registry.execute(
        &mut app,
        governance.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days,
            description: "Some service".into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        governance,
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute_with_funds(
        &mut app,
        worker.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::RegisterChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name],
        },
    );
    assert!(res.is_ok());

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::UnbondWorker {
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());
    assert_eq!(
        app.wrap()
            .query_balance(worker.clone(), AXL_DENOMINATION)
            .unwrap()
            .amount
            .u128(),
        initial_bal - min_worker_bond.u128()
    );

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::ClaimStake {
            service_name: service_name.into(),
        },
    );
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err().to_string(),
        axelar_wasm_std::ContractError::from(ContractError::InvalidBondingState(
            BondingState::Unbonding {
                unbonded_at: app.block_info().time,
                amount: min_worker_bond,
            }
        ))
        .to_string()
    );
    assert_eq!(
        app.wrap()
            .query_balance(worker.clone(), AXL_DENOMINATION)
            .unwrap()
            .amount
            .u128(),
        initial_bal - min_worker_bond.u128()
    );

    let block = app.block_info();
    app.set_block(BlockInfo {
        height: block.height + 1,
        time: app
            .block_info()
            .time
            .plus_days(unbonding_period_days.into()),
        ..block
    });

    let res = service_registry.execute(
        &mut app,
        worker.clone(),
        &ExecuteMsg::ClaimStake {
            service_name: service_name.into(),
        },
    );
    assert!(res.is_ok());

    assert_eq!(
        app.wrap()
            .query_balance(worker, AXL_DENOMINATION)
            .unwrap()
            .amount
            .u128(),
        initial_bal
    );
}

#[test]
fn get_active_workers_should_not_return_less_than_min() {
    let workers = vec![Addr::unchecked("worker1"), Addr::unchecked("worker2")];
    let min_num_workers = workers.len() as u16;

    let mut app = App::new(|router, _, storage| {
        for worker in &workers {
            router
                .bank
                .init_balance(storage, worker, coins(100000, AXL_DENOMINATION))
                .unwrap()
        }
    });

    let governance = Addr::unchecked("gov");
    let service_registry =
        test_utils::ServiceRegistryContract::instantiate_contract(&mut app, governance.clone());

    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let _ = service_registry
        .execute(
            &mut app,
            governance.clone(),
            &ExecuteMsg::RegisterService {
                service_name: service_name.into(),
                service_contract: Addr::unchecked("nowhere"),
                min_num_workers,
                max_num_workers: Some(100),
                min_worker_bond,
                bond_denom: AXL_DENOMINATION.into(),
                unbonding_period_days: 10,
                description: "Some service".into(),
            },
        )
        .unwrap();

    let _ = service_registry
        .execute(
            &mut app,
            governance,
            &ExecuteMsg::AuthorizeWorkers {
                workers: workers.iter().map(|w| w.into()).collect(),
                service_name: service_name.into(),
            },
        )
        .unwrap();

    let chain_name = ChainName::from_str("ethereum").unwrap();

    for worker in &workers {
        // should return err until all workers are registered
        let res: StdResult<Vec<WeightedWorker>> = service_registry.query(
            &app,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name: chain_name.clone(),
            },
        );
        assert!(res.is_err());

        let _ = service_registry
            .execute_with_funds(
                &mut app,
                worker.clone(),
                &ExecuteMsg::BondWorker {
                    service_name: service_name.into(),
                },
                &coins(min_worker_bond.u128(), AXL_DENOMINATION),
            )
            .unwrap();

        let _ = service_registry
            .execute(
                &mut app,
                worker.clone(),
                &ExecuteMsg::RegisterChainSupport {
                    service_name: service_name.into(),
                    chains: vec![chain_name.clone()],
                },
            )
            .unwrap();
    }

    // all workers registered, should not return err now
    let res: StdResult<Vec<WeightedWorker>> = service_registry.query(
        &app,
        &QueryMsg::GetActiveWorkers {
            service_name: service_name.into(),
            chain_name: chain_name.clone(),
        },
    );
    assert!(res.is_ok());

    // remove one, should return err again
    let _ = service_registry
        .execute(
            &mut app,
            workers[0].clone(),
            &ExecuteMsg::DeregisterChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
        )
        .unwrap();
    let res: StdResult<Vec<WeightedWorker>> = service_registry.query(
        &app,
        &QueryMsg::GetActiveWorkers {
            service_name: service_name.into(),
            chain_name: chain_name.clone(),
        },
    );
    assert!(res.is_err());
}

use std::{str::FromStr, vec};

use connection_router::state::ChainName;
use cosmwasm_std::{coins, Addr, BlockInfo, Uint128};
use cw_multi_test::{App, ContractWrapper, Executor};
use service_registry::{
    contract::{execute, instantiate, query},
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{AuthorizationState, BondingState, Worker},
    ContractError,
};

const AXL_DENOMINATION: &str = "uaxl";

#[test]
fn register_service() {
    let mut app = App::default();
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let res = app.execute_contract(
        governance,
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());
    let res = app.execute_contract(
        Addr::unchecked("some other account"),
        contract_addr,
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
        &[],
    );
    assert!(!res.is_ok());
    assert_eq!(
        res.unwrap_err()
            .downcast::<axelar_wasm_std::ContractError>()
            .unwrap()
            .to_string(),
        axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
    );
}

#[test]
fn authorize_worker() {
    let mut app = App::default();
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance,
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![Addr::unchecked("worker").into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());
    let res = app.execute_contract(
        Addr::unchecked("some other address"),
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![Addr::unchecked("worker").into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert_eq!(
        res.unwrap_err()
            .downcast::<axelar_wasm_std::ContractError>()
            .unwrap()
            .to_string(),
        axelar_wasm_std::ContractError::from(ContractError::Unauthorized).to_string()
    );
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
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance,
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());
    let res = app.execute_contract(
        worker,
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());
}

#[test]
fn declare_chain_support() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance,
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(
        workers,
        vec![Worker {
            address: worker,
            bonding_state: BondingState::Bonded {
                amount: min_worker_bond
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: service_name.into()
        }]
    );

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name: ChainName::from_str("some other chain").unwrap(),
            },
        )
        .unwrap();
    assert_eq!(workers, vec![])
}

#[test]
fn declare_and_denounce_support_for_single_chain() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    // Denounce chain support
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DenounceChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![]);
}

#[test]
fn declare_and_denounce_support_for_multiple_chains() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
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

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: chains.clone(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DenounceChainSupport {
            service_name: service_name.into(),
            chains: chains.clone(),
        },
        &[],
    );
    assert!(res.is_ok());

    for chain in chains {
        let workers: Vec<Worker> = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name: chain.clone(),
                },
            )
            .unwrap();
        assert_eq!(workers, vec![]);
    }
}

#[test]
fn declare_for_multiple_chains_denounce_for_first_one() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
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

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: chains.clone(),
        },
        &[],
    );
    assert!(res.is_ok());

    // Denounce only the first chain
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DenounceChainSupport {
            service_name: service_name.into(),
            chains: vec![chains[0].clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    // Verify that worker is not associated with the denounced chain
    let denounced_chain = chains[0].clone();
    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name: denounced_chain.clone(),
            },
        )
        .unwrap();
    assert_eq!(workers, vec![]);

    // Verify that worker is still associated with other chains
    for chain in chains.iter().skip(1) {
        let workers: Vec<Worker> = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::GetActiveWorkers {
                    service_name: service_name.into(),
                    chain_name: chain.clone(),
                },
            )
            .unwrap();
        assert_eq!(
            workers,
            vec![Worker {
                address: worker.clone(),
                bonding_state: BondingState::Bonded {
                    amount: min_worker_bond
                },
                authorization_state: AuthorizationState::Authorized,
                service_name: service_name.into()
            }]
        );
    }
}

#[test]
fn declare_support_for_a_chain_denounce_support_for_another_chain() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let second_chain_name = ChainName::from_str("avalanche").unwrap();
    // Denounce support for another chain
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DenounceChainSupport {
            service_name: service_name.into(),
            chains: vec![second_chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(
        workers,
        vec![Worker {
            address: worker,
            bonding_state: BondingState::Bonded {
                amount: min_worker_bond
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: service_name.into()
        }]
    );
}

#[test]
fn declare_denounce_declare_support_for_single_chain() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DenounceChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    // Second support declaration
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(
        workers,
        vec![Worker {
            address: worker,
            bonding_state: BondingState::Bonded {
                amount: min_worker_bond
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: service_name.into()
        }]
    );
}

#[test]
fn denounce_previously_unsupported_single_chain() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DenounceChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name: ChainName::from_str("some other chain").unwrap(),
            },
        )
        .unwrap();
    assert_eq!(workers, vec![])
}

#[test]
fn declare_and_denounce_support_for_single_chain_unbonded() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DenounceChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![]);
}

#[test]
fn denounce_from_unregistered_worker_single_chain() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let err = app
        .execute_contract(
            worker.clone(),
            contract_addr.clone(),
            &ExecuteMsg::DenounceChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        err.downcast::<axelar_wasm_std::ContractError>()
            .unwrap()
            .to_string(),
        axelar_wasm_std::ContractError::from(ContractError::WorkerNotFound).to_string()
    );

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr,
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(workers, vec![]);
}

#[test]
fn denounce_single_chain_for_nonexistent_service() {
    let worker = Addr::unchecked("worker");
    let mut app = App::new(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &worker, coins(100000, AXL_DENOMINATION))
            .unwrap()
    });
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let chain_name = ChainName::from_str("ethereum").unwrap();
    let err = app
        .execute_contract(
            worker.clone(),
            contract_addr.clone(),
            &ExecuteMsg::DenounceChainSupport {
                service_name: service_name.into(),
                chains: vec![chain_name.clone()],
            },
            &[],
        )
        .unwrap_err();

    assert_eq!(
        err.downcast::<axelar_wasm_std::ContractError>()
            .unwrap()
            .to_string(),
        axelar_wasm_std::ContractError::from(ContractError::ServiceNotFound).to_string()
    );
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
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance,
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    assert!(res.is_ok());
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::UnbondWorker {
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr,
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
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), "funnydenom"),
    );
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err()
            .downcast::<axelar_wasm_std::ContractError>()
            .unwrap()
            .to_string(),
        axelar_wasm_std::ContractError::from(ContractError::WrongDenom).to_string()
    );
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
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
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
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance,
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128() / 2, AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
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
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance,
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(
        workers,
        vec![Worker {
            address: worker,
            bonding_state: BondingState::Bonded {
                amount: min_worker_bond
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: service_name.into()
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
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let min_worker_bond = Uint128::new(100);
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
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
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance,
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.clone()],
        },
        &[],
    );
    assert!(res.is_ok());

    assert!(res.is_ok());
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::UnbondWorker {
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::GetActiveWorkers {
                service_name: service_name.into(),
                chain_name,
            },
        )
        .unwrap();
    assert_eq!(
        workers,
        vec![Worker {
            address: worker,
            bonding_state: BondingState::Bonded {
                amount: min_worker_bond
            },
            authorization_state: AuthorizationState::Authorized,
            service_name: service_name.into()
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
    let code = ContractWrapper::new(execute, instantiate, query);
    let code_id = app.store_code(Box::new(code));
    let governance = Addr::unchecked("gov");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("anyone"),
            &InstantiateMsg {
                governance_account: governance.clone().into(),
            },
            &[],
            "service_registry",
            None,
        )
        .unwrap();
    let service_name = "validators";
    let unbonding_period_days = 1;
    let res = app.execute_contract(
        governance.clone(),
        contract_addr.clone(),
        &ExecuteMsg::RegisterService {
            service_name: service_name.into(),
            service_contract: Addr::unchecked("nowhere"),
            min_num_workers: 0,
            max_num_workers: Some(100),
            min_worker_bond,
            bond_denom: AXL_DENOMINATION.into(),
            unbonding_period_days: unbonding_period_days.clone(),
            description: "Some service".into(),
        },
        &[],
    );
    assert!(res.is_ok());

    let res = app.execute_contract(
        governance,
        contract_addr.clone(),
        &ExecuteMsg::AuthorizeWorkers {
            workers: vec![worker.clone().into()],
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(res.is_ok());
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::BondWorker {
            service_name: service_name.into(),
        },
        &coins(min_worker_bond.u128(), AXL_DENOMINATION),
    );
    assert!(res.is_ok());

    let chain_name = ChainName::from_str("ethereum").unwrap();
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name],
        },
        &[],
    );
    assert!(res.is_ok());

    assert!(res.is_ok());
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::UnbondWorker {
            service_name: service_name.into(),
        },
        &[],
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

    assert!(res.is_ok());
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::ClaimStake {
            service_name: service_name.into(),
        },
        &[],
    );
    assert!(!res.is_ok());
    assert_eq!(
        res.unwrap_err()
            .downcast::<axelar_wasm_std::ContractError>()
            .unwrap()
            .to_string(),
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

    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::ClaimStake {
            service_name: service_name.into(),
        },
        &[],
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

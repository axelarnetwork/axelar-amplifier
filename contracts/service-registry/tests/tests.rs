use std::vec;

use cosmwasm_std::{coins, Addr, BlockInfo, Uint128};
use cw_multi_test::{App, ContractWrapper, Executor};
use service_registry::{
    contract::{execute, instantiate, query, AXL_DENOMINATION},
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{AuthorizationState, BondingState, Worker},
    ContractError,
};

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
            unbonding_period_days: 10,
            description: "Some service".into(),
        },
        &[],
    );
    assert!(!res.is_ok());
    assert_eq!(
        ContractError::Unauthorized {},
        res.unwrap_err().downcast().unwrap()
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
        ContractError::Unauthorized {},
        res.unwrap_err().downcast().unwrap()
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

    let chain_name = "ethereum";
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.into()],
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
                chain_name: chain_name.into(),
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
                chain_name: "some other chain".into(),
            },
        )
        .unwrap();
    assert_eq!(workers, vec![])
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

    let chain_name = "ethereum";
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.into()],
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
                chain_name: chain_name.into(),
            },
        )
        .unwrap();
    assert_eq!(workers, vec![])
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

    let chain_name = "ethereum";
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.into()],
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
                chain_name: chain_name.into(),
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

    let chain_name = "ethereum";
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.into()],
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
                chain_name: chain_name.into(),
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

    let chain_name = "ethereum";
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.into()],
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
                chain_name: chain_name.into(),
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

    let chain_name = "ethereum";
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.into()],
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
                chain_name: chain_name.into(),
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

    let chain_name = "ethereum";
    let res = app.execute_contract(
        worker.clone(),
        contract_addr.clone(),
        &ExecuteMsg::DeclareChainSupport {
            service_name: service_name.into(),
            chains: vec![chain_name.into()],
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
        ContractError::InvalidBondingState(BondingState::Unbonding {
            unbonded_at: app.block_info().time,
            amount: min_worker_bond,
        }),
        res.unwrap_err().downcast().unwrap()
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

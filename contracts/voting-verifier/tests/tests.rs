use cosmwasm_std::{from_binary, Addr, Uint64};
use cw_multi_test::{App, ContractWrapper, Executor};

use axelar_wasm_std::operators::Operators;
use axelar_wasm_std::{nonempty, Threshold};
use connection_router::state::{ChainName, CrossChainId, Message, MessageId, ID_SEPARATOR};
use service_registry::state::Worker;
use voting_verifier::{contract, error::ContractError, msg};

use crate::mock::make_mock_service_registry;

pub mod mock;

const SENDER: &str = "sender";
fn source_chain() -> ChainName {
    "source_chain".parse().unwrap()
}

fn initialize_contract(app: &mut App, service_registry_address: nonempty::String) -> Addr {
    let msg = msg::InstantiateMsg {
        service_registry_address,
        service_name: "service_name".parse().unwrap(),
        voting_threshold: Threshold::try_from((1u64, 2u64)).unwrap(),
        block_expiry: 100,
        confirmation_height: 100,
        source_gateway_address: "gateway_address".parse().unwrap(),
        source_chain: source_chain(),
    };

    let code = ContractWrapper::new(contract::execute, contract::instantiate, contract::query);
    let code_id = app.store_code(Box::new(code));

    let address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked(SENDER),
            &msg,
            &[],
            "voting-verifier",
            None,
        )
        .unwrap();

    address
}

fn message_id(id: &str, index: u64) -> String {
    format!("{}{}{}", id, ID_SEPARATOR, index)
}

fn messages(len: u64) -> Vec<Message> {
    (0..len)
        .map(|i| Message {
            cc_id: CrossChainId {
                chain: source_chain(),
                id: format!("id:{i}").parse().unwrap(),
            },
            source_address: format!("source_address{i}").parse().unwrap(),
            destination_chain: format!("destination_chain{i}").parse().unwrap(),
            destination_address: format!("destination_address{i}").parse().unwrap(),
            payload_hash: vec![0, 0, 0, 0].into(),
        })
        .collect()
}

#[test]
fn should_failed_if_messages_are_not_from_same_source() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    let msg = msg::ExecuteMsg::VerifyMessages {
        messages: vec![
            Message {
                cc_id: CrossChainId {
                    chain: source_chain(),
                    id: "id:1".parse().unwrap(),
                },
                source_address: "source_address1".parse().unwrap(),
                destination_chain: "destination_chain1".parse().unwrap(),
                destination_address: "destination_address1".parse().unwrap(),
                payload_hash: vec![0, 0, 0, 0].into(),
            },
            Message {
                cc_id: CrossChainId {
                    chain: "other_chain".parse().unwrap(),
                    id: "id:2".parse().unwrap(),
                },
                source_address: "source_address2".parse().unwrap(),
                destination_chain: "destination_chain2".parse().unwrap(),
                destination_address: "destination_address2".parse().unwrap(),
                payload_hash: vec![0, 0, 0, 0].into(),
            },
        ],
    };

    let err = app
        .execute_contract(Addr::unchecked(SENDER), contract_address, &msg, &[])
        .unwrap_err();
    assert_eq!(
        err.downcast::<axelar_wasm_std::ContractError>()
            .unwrap()
            .to_string(),
        axelar_wasm_std::ContractError::from(ContractError::SourceChainMismatch(source_chain(),))
            .to_string()
    );
}

#[test]
fn should_verify_messages_if_not_verified() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    let msg = msg::ExecuteMsg::VerifyMessages {
        messages: messages(2),
    };

    let res = app
        .execute_contract(Addr::unchecked(SENDER), contract_address, &msg, &[])
        .unwrap();
    let reply: msg::VerifyMessagesResponse = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(reply.verification_statuses.len(), 2);
    assert_eq!(
        reply.verification_statuses,
        vec![
            (
                CrossChainId {
                    id: "id:0".parse().unwrap(),
                    chain: source_chain()
                },
                false
            ),
            (
                CrossChainId {
                    id: "id:1".parse().unwrap(),
                    chain: source_chain()
                },
                false
            ),
        ]
    );
}

#[test]
fn should_query_message_statuses() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    let messages = messages(10);

    let msg = msg::ExecuteMsg::VerifyMessages {
        messages: messages.clone(),
    };

    let res = app
        .execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[])
        .unwrap();

    let reply: msg::VerifyMessagesResponse = from_binary(&res.data.unwrap()).unwrap();

    assert_eq!(reply.verification_statuses.len(), messages.len());
    assert_eq!(
        reply.verification_statuses,
        messages
            .iter()
            .map(|message| (message.cc_id.clone(), false))
            .collect::<Vec<(CrossChainId, bool)>>()
    );

    let query = msg::QueryMsg::IsVerified {
        messages: messages.clone(),
    };

    let statuses: Vec<(CrossChainId, bool)> = app
        .wrap()
        .query_wasm_smart(contract_address.clone(), &query)
        .unwrap();

    assert_eq!(
        statuses,
        messages
            .iter()
            .map(|message| (message.cc_id.clone(), false))
            .collect::<Vec<(CrossChainId, bool)>>()
    );

    let msg: msg::ExecuteMsg = msg::ExecuteMsg::Vote {
        poll_id: Uint64::one().into(),
        votes: (0..messages.len())
            .map(|i| i % 2 == 0)
            .collect::<Vec<bool>>(),
    };

    app.execute_contract(
        Addr::unchecked("addr1"),
        contract_address.clone(),
        &msg,
        &[],
    )
    .unwrap();
    app.execute_contract(
        Addr::unchecked("addr2"),
        contract_address.clone(),
        &msg,
        &[],
    )
    .unwrap();

    let msg: msg::ExecuteMsg = msg::ExecuteMsg::EndPoll {
        poll_id: Uint64::one().into(),
    };
    app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[])
        .unwrap();

    let statuses: Vec<(CrossChainId, bool)> = app
        .wrap()
        .query_wasm_smart(contract_address.clone(), &query)
        .unwrap();

    assert_eq!(
        statuses,
        messages
            .iter()
            .enumerate()
            .map(|(i, message)| (message.cc_id.clone(), i % 2 == 0))
            .collect::<Vec<(CrossChainId, bool)>>()
    );
}

#[test]
fn should_start_worker_set_confirmation() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    let operators = Operators {
        weights_by_addresses: vec![(vec![0, 1, 0, 1].into(), 1u64.into())],
        threshold: 1u64.into(),
    };
    let msg = msg::ExecuteMsg::ConfirmWorkerSet {
        message_id: MessageId::try_from(message_id("id", 0)).unwrap(),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query = msg::QueryMsg::IsWorkerSetConfirmed {
        new_operators: operators,
    };
    let res: Result<bool, _> = app.wrap().query_wasm_smart(contract_address, &query);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), false);
}

#[test]
fn should_confirm_worker_set() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            service_registry_address,
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: "service_name".to_string(),
                chain_name: source_chain().to_string(),
            },
        )
        .unwrap();

    let operators = Operators {
        weights_by_addresses: vec![(vec![0, 1, 0, 1].into(), 1u64.into())],
        threshold: 1u64.into(),
    };
    let msg = msg::ExecuteMsg::ConfirmWorkerSet {
        message_id: MessageId::try_from(message_id("id", 0)).unwrap(),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 1u64.into(),
        votes: vec![true],
    };
    for worker in workers {
        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 1u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query = msg::QueryMsg::IsWorkerSetConfirmed {
        new_operators: operators,
    };
    let res: Result<bool, _> = app.wrap().query_wasm_smart(contract_address, &query);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), true);
}

#[test]
fn should_not_confirm_worker_set() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            service_registry_address,
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: "service_name".to_string(),
                chain_name: source_chain().to_string(),
            },
        )
        .unwrap();

    let operators = Operators {
        weights_by_addresses: vec![(vec![0, 1, 0, 1].into(), 1u64.into())],
        threshold: 1u64.into(),
    };
    let msg = msg::ExecuteMsg::ConfirmWorkerSet {
        message_id: MessageId::try_from(message_id("id", 0)).unwrap(),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 1u64.into(),
        votes: vec![false],
    };
    for worker in workers {
        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 1u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query = msg::QueryMsg::IsWorkerSetConfirmed {
        new_operators: operators,
    };
    let res: Result<bool, _> = app.wrap().query_wasm_smart(contract_address, &query);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), false);
}

#[test]
fn should_confirm_worker_set_after_failed() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            service_registry_address,
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: "service_name".to_string(),
                chain_name: source_chain().to_string(),
            },
        )
        .unwrap();

    let operators = Operators {
        weights_by_addresses: vec![(vec![0, 1, 0, 1].into(), 1u64.into())],
        threshold: 1u64.into(),
    };
    let msg = msg::ExecuteMsg::ConfirmWorkerSet {
        message_id: MessageId::try_from(message_id("id", 0)).unwrap(),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 1u64.into(),
        votes: vec![false],
    };
    for worker in &workers {
        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 1u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query = msg::QueryMsg::IsWorkerSetConfirmed {
        new_operators: operators.clone(),
    };
    let res: Result<bool, _> = app
        .wrap()
        .query_wasm_smart(contract_address.clone(), &query);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), false);

    // try again, and this time vote true
    let msg = msg::ExecuteMsg::ConfirmWorkerSet {
        message_id: MessageId::try_from(message_id("id", 0)).unwrap(),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 2u64.into(),
        votes: vec![true],
    };
    for worker in workers {
        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 2u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query = msg::QueryMsg::IsWorkerSetConfirmed {
        new_operators: operators,
    };
    let res: Result<bool, _> = app.wrap().query_wasm_smart(contract_address, &query);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), true);
}

#[test]
fn should_not_confirm_twice() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    let workers: Vec<Worker> = app
        .wrap()
        .query_wasm_smart(
            service_registry_address,
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: "service_name".to_string(),
                chain_name: source_chain().to_string(),
            },
        )
        .unwrap();

    let operators = Operators {
        weights_by_addresses: vec![(vec![0, 1, 0, 1].into(), 1u64.into())],
        threshold: 1u64.into(),
    };
    let msg = msg::ExecuteMsg::ConfirmWorkerSet {
        message_id: MessageId::try_from(message_id("id", 0)).unwrap(),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 1u64.into(),
        votes: vec![true],
    };
    for worker in workers {
        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 1u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    // try again, should fail
    let msg = msg::ExecuteMsg::ConfirmWorkerSet {
        message_id: MessageId::try_from(message_id("id", 0)).unwrap(),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err()
            .downcast::<axelar_wasm_std::ContractError>()
            .unwrap()
            .to_string(),
        axelar_wasm_std::ContractError::from(ContractError::WorkerSetAlreadyConfirmed).to_string()
    );
}

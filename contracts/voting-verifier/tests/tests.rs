use axelar_wasm_std::voting::Vote;
use cosmwasm_std::{from_binary, Addr, Uint64};
use cw_multi_test::{App, ContractWrapper, Executor};

use axelar_wasm_std::operators::Operators;
use axelar_wasm_std::{nonempty, Threshold, VerificationStatus};
use connection_router::state::{ChainName, CrossChainId, Message, ID_SEPARATOR};
use mock::make_mock_rewards;
use service_registry::state::Worker;
use voting_verifier::events::TxEventConfirmation;
use voting_verifier::{contract, error::ContractError, msg};

use crate::mock::make_mock_service_registry;

pub mod mock;

const SENDER: &str = "sender";
const POLL_BLOCK_EXPIRY: u64 = 100;
fn source_chain() -> ChainName {
    "source_chain".parse().unwrap()
}

fn initialize_contract(app: &mut App, service_registry_address: nonempty::String) -> Addr {
    let rewards_address = make_mock_rewards(app).into();

    let msg = msg::InstantiateMsg {
        service_registry_address,
        service_name: "service_name".parse().unwrap(),
        voting_threshold: Threshold::try_from((2u64, 3u64))
            .unwrap()
            .try_into()
            .unwrap(),
        block_expiry: POLL_BLOCK_EXPIRY,
        confirmation_height: 100,
        source_gateway_address: "gateway_address".parse().unwrap(),
        source_chain: source_chain(),
        rewards_address,
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

fn message_id(id: &str, index: u64) -> nonempty::String {
    format!("{}{}{}", id, ID_SEPARATOR, index)
        .try_into()
        .unwrap()
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
            payload_hash: [0; 32],
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
                payload_hash: [0; 32],
            },
            Message {
                cc_id: CrossChainId {
                    chain: "other_chain".parse().unwrap(),
                    id: "id:2".parse().unwrap(),
                },
                source_address: "source_address2".parse().unwrap(),
                destination_chain: "destination_chain2".parse().unwrap(),
                destination_address: "destination_address2".parse().unwrap(),
                payload_hash: [0; 32],
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
                VerificationStatus::None
            ),
            (
                CrossChainId {
                    id: "id:1".parse().unwrap(),
                    chain: source_chain()
                },
                VerificationStatus::None
            ),
        ]
    );
}

#[test]
fn should_not_verify_messages_if_in_progress() {
    let mut app = App::default();
    let messages_in_progress = 3;
    let new_messages = 2;

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    app.execute_contract(
        Addr::unchecked(SENDER),
        contract_address.clone(),
        &msg::ExecuteMsg::VerifyMessages {
            messages: messages(messages_in_progress),
        },
        &[],
    )
    .unwrap();

    let res = app
        .execute_contract(
            Addr::unchecked(SENDER),
            contract_address,
            &msg::ExecuteMsg::VerifyMessages {
                messages: messages(messages_in_progress + new_messages), // creates the same messages + some new ones
            },
            &[],
        )
        .unwrap();

    let messages: Vec<TxEventConfirmation> = serde_json::from_str(
        &res.events
            .into_iter()
            .find(|event| event.ty == "wasm-messages_poll_started")
            .unwrap()
            .attributes
            .into_iter()
            .find_map(|attribute| {
                if attribute.key == "messages" {
                    Some(attribute.value)
                } else {
                    None
                }
            })
            .unwrap(),
    )
    .unwrap();

    assert_eq!(messages.len() as u64, new_messages);
}

#[test]
fn should_retry_if_message_not_verified() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    let msg = msg::ExecuteMsg::VerifyMessages {
        messages: messages(1),
    };
    app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[])
        .unwrap();

    app.update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    app.execute_contract(
        Addr::unchecked(SENDER),
        contract_address.clone(),
        &msg::ExecuteMsg::EndPoll {
            poll_id: Uint64::one().into(),
        },
        &[],
    )
    .unwrap();

    // retries same message
    let res = app
        .execute_contract(Addr::unchecked(SENDER), contract_address, &msg, &[])
        .unwrap();

    let messages: Vec<TxEventConfirmation> = serde_json::from_str(
        &res.events
            .into_iter()
            .find(|event| event.ty == "wasm-messages_poll_started")
            .unwrap()
            .attributes
            .into_iter()
            .find_map(|attribute| {
                if attribute.key == "messages" {
                    Some(attribute.value)
                } else {
                    None
                }
            })
            .unwrap(),
    )
    .unwrap();

    assert_eq!(messages.len() as u64, 1);
}

#[test]
fn should_retry_if_status_not_final() {
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
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let messages = messages(4);

    let msg_verify = msg::ExecuteMsg::VerifyMessages {
        messages: messages.clone(),
    };
    let res = app.execute_contract(
        Addr::unchecked(SENDER),
        contract_address.clone(),
        &msg_verify,
        &[],
    );
    assert!(res.is_ok());

    workers.iter().enumerate().for_each(|(i, worker)| {
        let msg = msg::ExecuteMsg::Vote {
            poll_id: 1u64.into(),
            votes: vec![
                Vote::SucceededOnChain,
                Vote::FailedOnChain,
                Vote::NotFound,
                if i % 2 == 0 {
                    Vote::SucceededOnChain
                } else {
                    Vote::FailedOnChain
                },
            ],
        };

        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    });

    app.update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 1u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query: msg::QueryMsg = msg::QueryMsg::GetMessagesStatus {
        messages: messages.clone(),
    };
    let res: Result<Vec<(CrossChainId, VerificationStatus)>, _> = app
        .wrap()
        .query_wasm_smart(contract_address.clone(), &query);
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        vec![
            (
                messages[0].cc_id.clone(),
                VerificationStatus::SucceededOnChain
            ),
            (messages[1].cc_id.clone(), VerificationStatus::FailedOnChain),
            (messages[2].cc_id.clone(), VerificationStatus::NotFound),
            (
                messages[3].cc_id.clone(),
                VerificationStatus::FailedToVerify
            )
        ]
    );

    let res = app.execute_contract(
        Addr::unchecked(SENDER),
        contract_address.clone(),
        &msg_verify,
        &[],
    );
    assert!(res.is_ok());

    let res: Result<Vec<(CrossChainId, VerificationStatus)>, _> =
        app.wrap().query_wasm_smart(contract_address, &query);
    assert!(res.is_ok());
    assert_eq!(
        res.unwrap(),
        vec![
            (
                messages[0].cc_id.clone(),
                VerificationStatus::SucceededOnChain
            ),
            (messages[1].cc_id.clone(), VerificationStatus::FailedOnChain),
            (messages[2].cc_id.clone(), VerificationStatus::InProgress),
            (messages[3].cc_id.clone(), VerificationStatus::InProgress)
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
            .map(|message| (message.cc_id.clone(), VerificationStatus::None))
            .collect::<Vec<(_, _)>>()
    );

    let query = msg::QueryMsg::GetMessagesStatus {
        messages: messages.clone(),
    };

    let statuses: Vec<(CrossChainId, VerificationStatus)> = app
        .wrap()
        .query_wasm_smart(contract_address.clone(), &query)
        .unwrap();

    assert_eq!(
        statuses,
        messages
            .iter()
            .map(|message| (message.cc_id.clone(), VerificationStatus::InProgress))
            .collect::<Vec<(_, _)>>()
    );

    let msg: msg::ExecuteMsg = msg::ExecuteMsg::Vote {
        poll_id: Uint64::one().into(),
        votes: (0..messages.len())
            .map(|i| {
                if i % 2 == 0 {
                    Vote::SucceededOnChain
                } else {
                    Vote::NotFound
                }
            })
            .collect::<Vec<_>>(),
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

    app.update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let msg: msg::ExecuteMsg = msg::ExecuteMsg::EndPoll {
        poll_id: Uint64::one().into(),
    };
    app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[])
        .unwrap();

    let statuses: Vec<(CrossChainId, VerificationStatus)> = app
        .wrap()
        .query_wasm_smart(contract_address.clone(), &query)
        .unwrap();

    assert_eq!(
        statuses,
        messages
            .iter()
            .enumerate()
            .map(|(i, message)| (
                message.cc_id.clone(),
                if i % 2 == 0 {
                    VerificationStatus::SucceededOnChain
                } else {
                    VerificationStatus::NotFound
                }
            ))
            .collect::<Vec<(_, _)>>()
    );
}

#[test]
fn should_start_worker_set_confirmation() {
    let mut app = App::default();

    let service_registry_address = make_mock_service_registry(&mut app);

    let contract_address =
        initialize_contract(&mut app, service_registry_address.as_ref().parse().unwrap());

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let msg = msg::ExecuteMsg::VerifyWorkerSet {
        message_id: message_id("id", 0),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query = msg::QueryMsg::GetWorkerSetStatus {
        new_operators: operators,
    };
    let res: Result<VerificationStatus, _> = app.wrap().query_wasm_smart(contract_address, &query);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), VerificationStatus::InProgress);
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
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let msg = msg::ExecuteMsg::VerifyWorkerSet {
        message_id: message_id("id", 0),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 1u64.into(),
        votes: vec![Vote::SucceededOnChain],
    };
    for worker in workers {
        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    app.update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 1u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query = msg::QueryMsg::GetWorkerSetStatus {
        new_operators: operators,
    };
    let res: Result<VerificationStatus, _> = app.wrap().query_wasm_smart(contract_address, &query);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), VerificationStatus::SucceededOnChain);
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
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let msg = msg::ExecuteMsg::VerifyWorkerSet {
        message_id: message_id("id", 0),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 1u64.into(),
        votes: vec![Vote::NotFound],
    };
    for worker in workers {
        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    app.update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 1u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query = msg::QueryMsg::GetWorkerSetStatus {
        new_operators: operators,
    };
    let res: Result<VerificationStatus, _> = app.wrap().query_wasm_smart(contract_address, &query);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), VerificationStatus::NotFound);
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
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let msg = msg::ExecuteMsg::VerifyWorkerSet {
        message_id: message_id("id", 0),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 1u64.into(),
        votes: vec![Vote::NotFound],
    };
    for worker in &workers {
        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    app.update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 1u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query = msg::QueryMsg::GetWorkerSetStatus {
        new_operators: operators.clone(),
    };
    let res: Result<VerificationStatus, _> = app
        .wrap()
        .query_wasm_smart(contract_address.clone(), &query);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), VerificationStatus::NotFound);

    // try again, and this time vote true
    let msg = msg::ExecuteMsg::VerifyWorkerSet {
        message_id: message_id("id", 0),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 2u64.into(),
        votes: vec![Vote::SucceededOnChain],
    };
    for worker in workers {
        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    app.update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 2u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let query = msg::QueryMsg::GetWorkerSetStatus {
        new_operators: operators,
    };
    let res: Result<VerificationStatus, _> = app.wrap().query_wasm_smart(contract_address, &query);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), VerificationStatus::SucceededOnChain);
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
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let msg = msg::ExecuteMsg::VerifyWorkerSet {
        message_id: message_id("id", 0),
        new_operators: operators.clone(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 1u64.into(),
        votes: vec![Vote::SucceededOnChain],
    };
    for worker in workers {
        let res = app.execute_contract(worker.address.clone(), contract_address.clone(), &msg, &[]);
        assert!(res.is_ok());
    }

    app.update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 1u64.into(),
    };
    let res = app.execute_contract(Addr::unchecked(SENDER), contract_address.clone(), &msg, &[]);
    assert!(res.is_ok());

    // try again, should fail
    let msg = msg::ExecuteMsg::VerifyWorkerSet {
        message_id: message_id("id", 0),
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

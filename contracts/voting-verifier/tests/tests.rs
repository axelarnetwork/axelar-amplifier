use axelar_wasm_std::voting::Vote;
use cosmwasm_std::{from_binary, Addr, Uint64};
use cw_multi_test::{App, Executor};

use axelar_wasm_std::operators::Operators;
use axelar_wasm_std::{nonempty, VerificationStatus};
use connection_router::state::{ChainName, CrossChainId, Message, ID_SEPARATOR};
use integration_tests::contract::Contract;
use mock::make_mock_rewards;
use service_registry::state::Worker;
use voting_verifier::events::TxEventConfirmation;
use voting_verifier::{error::ContractError, msg};

use crate::mock::make_mock_service_registry;
use crate::test_utils::VotingVerifierContract;

pub mod mock;
mod test_utils;

const SENDER: &str = "sender";
const POLL_BLOCK_EXPIRY: u64 = 100;
fn source_chain() -> ChainName {
    "source_chain".parse().unwrap()
}

struct TestConfig {
    app: App,
    service_registry_address: Addr,
    voting_verifier: VotingVerifierContract,
}

fn setup() -> TestConfig {
    let mut app = App::default();
    let service_registry_address = make_mock_service_registry(&mut app);
    let rewards_address: String = make_mock_rewards(&mut app).into();
    let voting_verifier = VotingVerifierContract::instantiate_contract(
        &mut app,
        service_registry_address.as_ref().parse().unwrap(),
        rewards_address.clone(),
    );
    TestConfig {
        app,
        service_registry_address,
        voting_verifier,
    }
}

fn initialize_contract(app: &mut App, service_registry_address: nonempty::String) -> Addr {
    let rewards_address: String = make_mock_rewards(app).into();
    let verifier_address = VotingVerifierContract::instantiate_contract(
        app,
        service_registry_address.clone(),
        rewards_address.clone(),
    );
    verifier_address.contract_addr
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
    let mut config = setup();

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
    let err = config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg)
        .unwrap_err();
    test_utils::are_contract_err_strings_equal(
        err,
        ContractError::SourceChainMismatch(source_chain()),
    );
}

#[test]
fn should_verify_messages_if_not_verified() {
    let mut config = setup();

    let msg = msg::ExecuteMsg::VerifyMessages {
        messages: messages(2),
    };

    let res = config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg)
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
    let mut config = setup();
    let messages_in_progress = 3;
    let new_messages = 2;

    config
        .voting_verifier
        .execute(
            &mut config.app,
            Addr::unchecked(SENDER),
            &msg::ExecuteMsg::VerifyMessages {
                messages: messages(messages_in_progress),
            },
        )
        .unwrap();

    let res = config
        .voting_verifier
        .execute(
            &mut config.app,
            Addr::unchecked(SENDER),
            &msg::ExecuteMsg::VerifyMessages {
                messages: messages(messages_in_progress + new_messages), // creates the same messages + some new ones
            },
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
    let mut config = setup();

    let msg = msg::ExecuteMsg::VerifyMessages {
        messages: messages(1),
    };
    config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg)
        .unwrap();

    config
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    config
        .voting_verifier
        .execute(
            &mut config.app,
            Addr::unchecked(SENDER),
            &msg::ExecuteMsg::EndPoll {
                poll_id: Uint64::one().into(),
            },
        )
        .unwrap();

    // retries same message
    let res = config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg)
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
    let mut config = setup();
    let workers: Vec<Worker> = config
        .app
        .wrap()
        .query_wasm_smart(
            config.service_registry_address,
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

    let res = config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg_verify);
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

        let res = config
            .voting_verifier
            .execute(&mut config.app, worker.address.clone(), &msg);
        assert!(res.is_ok());
    });

    config
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let msg = msg::ExecuteMsg::EndPoll {
        poll_id: 1u64.into(),
    };

    let res = config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg);
    assert!(res.is_ok());

    let res: Vec<(CrossChainId, VerificationStatus)> = config.voting_verifier.query(
        &config.app,
        &msg::QueryMsg::GetMessagesStatus {
            messages: messages.clone(),
        },
    );
    assert_eq!(
        res,
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

    let res = config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg_verify);
    assert!(res.is_ok());

    let res: Vec<(CrossChainId, VerificationStatus)> = config.voting_verifier.query(
        &config.app,
        &msg::QueryMsg::GetMessagesStatus {
            messages: messages.clone(),
        },
    );
    assert_eq!(
        res,
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
    let mut config = setup();

    let messages = messages(10);
    let msg = msg::ExecuteMsg::VerifyMessages {
        messages: messages.clone(),
    };

    let res = config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg)
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

    let statuses: Vec<(CrossChainId, VerificationStatus)> = config.voting_verifier.query(
        &config.app,
        &msg::QueryMsg::GetMessagesStatus {
            messages: messages.clone(),
        },
    );
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

    config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked("addr1"), &msg)
        .unwrap();

    config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked("addr2"), &msg)
        .unwrap();

    config
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let msg: msg::ExecuteMsg = msg::ExecuteMsg::EndPoll {
        poll_id: Uint64::one().into(),
    };

    config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg)
        .unwrap();

    let statuses: Vec<(CrossChainId, VerificationStatus)> = config.voting_verifier.query(
        &config.app,
        &msg::QueryMsg::GetMessagesStatus {
            messages: messages.clone(),
        },
    );

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
    let mut config = setup();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let msg = msg::ExecuteMsg::VerifyWorkerSet {
        message_id: message_id("id", 0),
        new_operators: operators.clone(),
    };
    let res = config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg);
    assert!(res.is_ok());

    let res: VerificationStatus = config.voting_verifier.query(
        &config.app,
        &msg::QueryMsg::GetWorkerSetStatus {
            new_operators: operators.clone(),
        },
    );
    assert_eq!(res, VerificationStatus::InProgress);
}

#[test]
fn should_confirm_worker_set() {
    let mut config = setup();

    let workers: Vec<Worker> = config
        .app
        .wrap()
        .query_wasm_smart(
            config.service_registry_address,
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
    let res = config
        .voting_verifier
        .execute(&mut config.app, Addr::unchecked(SENDER), &msg);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 1u64.into(),
        votes: vec![Vote::SucceededOnChain],
    };
    for worker in workers {
        let res = config
            .voting_verifier
            .execute(&mut config.app, worker.address.clone(), &msg);
        assert!(res.is_ok());
    }

    config
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let res = config.voting_verifier.execute(
        &mut config.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::EndPoll {
            poll_id: 1u64.into(),
        },
    );
    assert!(res.is_ok());

    let res: VerificationStatus = config.voting_verifier.query(
        &config.app,
        &msg::QueryMsg::GetWorkerSetStatus {
            new_operators: operators.clone(),
        },
    );
    assert_eq!(res, VerificationStatus::SucceededOnChain);
}

#[test]
fn should_not_confirm_worker_set() {
    let mut config = setup();

    let workers: Vec<Worker> = config
        .app
        .wrap()
        .query_wasm_smart(
            config.service_registry_address,
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: "service_name".to_string(),
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let res = config.voting_verifier.execute(
        &mut config.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::VerifyWorkerSet {
            message_id: message_id("id", 0),
            new_operators: operators.clone(),
        },
    );
    assert!(res.is_ok());

    for worker in workers {
        let res = config.voting_verifier.execute(
            &mut config.app,
            worker.address.clone(),
            &msg::ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![Vote::NotFound],
            },
        );
        assert!(res.is_ok());
    }

    config
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let res = config.voting_verifier.execute(
        &mut config.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::EndPoll {
            poll_id: 1u64.into(),
        },
    );
    assert!(res.is_ok());

    let res: VerificationStatus = config.voting_verifier.query(
        &config.app,
        &msg::QueryMsg::GetWorkerSetStatus {
            new_operators: operators.clone(),
        },
    );
    assert_eq!(res, VerificationStatus::NotFound);
}

#[test]
fn should_confirm_worker_set_after_failed() {
    let mut config = setup();

    let workers: Vec<Worker> = config
        .app
        .wrap()
        .query_wasm_smart(
            config.service_registry_address,
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: "service_name".to_string(),
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let res = config.voting_verifier.execute(
        &mut config.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::VerifyWorkerSet {
            message_id: message_id("id", 0),
            new_operators: operators.clone(),
        },
    );
    assert!(res.is_ok());

    for worker in &workers {
        let res = config.voting_verifier.execute(
            &mut config.app,
            worker.address.clone(),
            &msg::ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![Vote::NotFound],
            },
        );
        assert!(res.is_ok());
    }

    config
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let res = config.voting_verifier.execute(
        &mut config.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::EndPoll {
            poll_id: 1u64.into(),
        },
    );
    assert!(res.is_ok());

    let res: VerificationStatus = config.voting_verifier.query(
        &config.app,
        &msg::QueryMsg::GetWorkerSetStatus {
            new_operators: operators.clone(),
        },
    );
    assert_eq!(res, VerificationStatus::NotFound);

    let res = config.voting_verifier.execute(
        &mut config.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::VerifyWorkerSet {
            message_id: message_id("id", 0),
            new_operators: operators.clone(),
        },
    );
    assert!(res.is_ok());

    for worker in workers {
        let res = config.voting_verifier.execute(
            &mut config.app,
            worker.address.clone(),
            &msg::ExecuteMsg::Vote {
                poll_id: 2u64.into(),
                votes: vec![Vote::SucceededOnChain],
            },
        );
        assert!(res.is_ok());
    }

    config
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let res = config.voting_verifier.execute(
        &mut config.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::EndPoll {
            poll_id: 2u64.into(),
        },
    );
    assert!(res.is_ok());

    let res: VerificationStatus = config.voting_verifier.query(
        &config.app,
        &msg::QueryMsg::GetWorkerSetStatus {
            new_operators: operators.clone(),
        },
    );
    assert_eq!(res, VerificationStatus::SucceededOnChain);
}

#[test]
fn should_not_confirm_twice() {
    let mut config = setup();

    let workers: Vec<Worker> = config
        .app
        .wrap()
        .query_wasm_smart(
            config.service_registry_address,
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: "service_name".to_string(),
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let res = config.voting_verifier.execute(
        &mut config.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::VerifyWorkerSet {
            message_id: message_id("id", 0),
            new_operators: operators.clone(),
        },
    );
    assert!(res.is_ok());

    for worker in workers {
        let res = config.voting_verifier.execute(
            &mut config.app,
            worker.address.clone(),
            &msg::ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![Vote::SucceededOnChain],
            },
        );
        assert!(res.is_ok());
    }

    config
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let res = config.voting_verifier.execute(
        &mut config.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::EndPoll {
            poll_id: 1u64.into(),
        },
    );
    assert!(res.is_ok());

    // try again, should fail
    let err = config
        .voting_verifier
        .execute(
            &mut config.app,
            Addr::unchecked(SENDER),
            &msg::ExecuteMsg::VerifyWorkerSet {
                message_id: message_id("id", 0),
                new_operators: operators.clone(),
            },
        )
        .unwrap_err();
    test_utils::are_contract_err_strings_equal(err, ContractError::WorkerSetAlreadyConfirmed);
}

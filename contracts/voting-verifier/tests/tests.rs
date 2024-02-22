use axelar_wasm_std::voting::Vote;
use cosmwasm_std::{from_binary, Addr, Uint64};
use cw_multi_test::{App, Executor};

use axelar_wasm_std::operators::Operators;
use axelar_wasm_std::{nonempty, VerificationStatus};
use connection_router_api::{ChainName, CrossChainId, Message, ID_SEPARATOR};
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

struct TestFixture {
    app: App,
    service_registry_address: Addr,
    voting_verifier: VotingVerifierContract,
}

fn setup() -> TestFixture {
    let mut app = App::default();
    let service_registry_address = make_mock_service_registry(&mut app);
    let rewards_address: String = make_mock_rewards(&mut app).into();
    let voting_verifier = VotingVerifierContract::instantiate_contract(
        &mut app,
        service_registry_address.as_ref().parse().unwrap(),
        rewards_address.clone(),
    );
    TestFixture {
        app,
        service_registry_address,
        voting_verifier,
    }
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
fn should_confirm_worker_set() {
    let mut fixture = setup();

    let workers: Vec<Worker> = fixture
        .app
        .wrap()
        .query_wasm_smart(
            fixture.service_registry_address,
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
    let res = fixture
        .voting_verifier
        .execute(&mut fixture.app, Addr::unchecked(SENDER), &msg);
    assert!(res.is_ok());

    let msg = msg::ExecuteMsg::Vote {
        poll_id: 1u64.into(),
        votes: vec![Vote::SucceededOnChain],
    };
    for worker in workers {
        let res = fixture
            .voting_verifier
            .execute(&mut fixture.app, worker.address.clone(), &msg);
        assert!(res.is_ok());
    }

    fixture
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let res = fixture.voting_verifier.execute(
        &mut fixture.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::EndPoll {
            poll_id: 1u64.into(),
        },
    );
    assert!(res.is_ok());

    let res: VerificationStatus = fixture.voting_verifier.query(
        &fixture.app,
        &msg::QueryMsg::GetWorkerSetStatus {
            new_operators: operators.clone(),
        },
    );
    assert_eq!(res, VerificationStatus::SucceededOnChain);
}

#[test]
fn should_not_confirm_worker_set() {
    let mut fixture = setup();

    let workers: Vec<Worker> = fixture
        .app
        .wrap()
        .query_wasm_smart(
            fixture.service_registry_address,
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: "service_name".to_string(),
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let res = fixture.voting_verifier.execute(
        &mut fixture.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::VerifyWorkerSet {
            message_id: message_id("id", 0),
            new_operators: operators.clone(),
        },
    );
    assert!(res.is_ok());

    for worker in workers {
        let res = fixture.voting_verifier.execute(
            &mut fixture.app,
            worker.address.clone(),
            &msg::ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![Vote::NotFound],
            },
        );
        assert!(res.is_ok());
    }

    fixture
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let res = fixture.voting_verifier.execute(
        &mut fixture.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::EndPoll {
            poll_id: 1u64.into(),
        },
    );
    assert!(res.is_ok());

    let res: VerificationStatus = fixture.voting_verifier.query(
        &fixture.app,
        &msg::QueryMsg::GetWorkerSetStatus {
            new_operators: operators.clone(),
        },
    );
    assert_eq!(res, VerificationStatus::NotFound);
}

#[test]
fn should_confirm_worker_set_after_failed() {
    let mut fixture = setup();

    let workers: Vec<Worker> = fixture
        .app
        .wrap()
        .query_wasm_smart(
            fixture.service_registry_address,
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: "service_name".to_string(),
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let res = fixture.voting_verifier.execute(
        &mut fixture.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::VerifyWorkerSet {
            message_id: message_id("id", 0),
            new_operators: operators.clone(),
        },
    );
    assert!(res.is_ok());

    for worker in &workers {
        let res = fixture.voting_verifier.execute(
            &mut fixture.app,
            worker.address.clone(),
            &msg::ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![Vote::NotFound],
            },
        );
        assert!(res.is_ok());
    }

    fixture
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let res = fixture.voting_verifier.execute(
        &mut fixture.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::EndPoll {
            poll_id: 1u64.into(),
        },
    );
    assert!(res.is_ok());

    let res: VerificationStatus = fixture.voting_verifier.query(
        &fixture.app,
        &msg::QueryMsg::GetWorkerSetStatus {
            new_operators: operators.clone(),
        },
    );
    assert_eq!(res, VerificationStatus::NotFound);

    let res = fixture.voting_verifier.execute(
        &mut fixture.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::VerifyWorkerSet {
            message_id: message_id("id", 0),
            new_operators: operators.clone(),
        },
    );
    assert!(res.is_ok());

    for worker in workers {
        let res = fixture.voting_verifier.execute(
            &mut fixture.app,
            worker.address.clone(),
            &msg::ExecuteMsg::Vote {
                poll_id: 2u64.into(),
                votes: vec![Vote::SucceededOnChain],
            },
        );
        assert!(res.is_ok());
    }

    fixture
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let res = fixture.voting_verifier.execute(
        &mut fixture.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::EndPoll {
            poll_id: 2u64.into(),
        },
    );
    assert!(res.is_ok());

    let res: VerificationStatus = fixture.voting_verifier.query(
        &fixture.app,
        &msg::QueryMsg::GetWorkerSetStatus {
            new_operators: operators.clone(),
        },
    );
    assert_eq!(res, VerificationStatus::SucceededOnChain);
}

#[test]
fn should_not_confirm_twice() {
    let mut fixture = setup();

    let workers: Vec<Worker> = fixture
        .app
        .wrap()
        .query_wasm_smart(
            fixture.service_registry_address,
            &service_registry::msg::QueryMsg::GetActiveWorkers {
                service_name: "service_name".to_string(),
                chain_name: source_chain(),
            },
        )
        .unwrap();

    let operators = Operators::new(vec![(vec![0, 1, 0, 1].into(), 1u64.into())], 1u64.into());
    let res = fixture.voting_verifier.execute(
        &mut fixture.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::VerifyWorkerSet {
            message_id: message_id("id", 0),
            new_operators: operators.clone(),
        },
    );
    assert!(res.is_ok());

    for worker in workers {
        let res = fixture.voting_verifier.execute(
            &mut fixture.app,
            worker.address.clone(),
            &msg::ExecuteMsg::Vote {
                poll_id: 1u64.into(),
                votes: vec![Vote::SucceededOnChain],
            },
        );
        assert!(res.is_ok());
    }

    fixture
        .app
        .update_block(|block| block.height += POLL_BLOCK_EXPIRY);

    let res = fixture.voting_verifier.execute(
        &mut fixture.app,
        Addr::unchecked(SENDER),
        &msg::ExecuteMsg::EndPoll {
            poll_id: 1u64.into(),
        },
    );
    assert!(res.is_ok());

    // try again, should fail
    let err = fixture
        .voting_verifier
        .execute(
            &mut fixture.app,
            Addr::unchecked(SENDER),
            &msg::ExecuteMsg::VerifyWorkerSet {
                message_id: message_id("id", 0),
                new_operators: operators.clone(),
            },
        )
        .unwrap_err();
    test_utils::are_contract_err_strings_equal(err, ContractError::WorkerSetAlreadyConfirmed);
}

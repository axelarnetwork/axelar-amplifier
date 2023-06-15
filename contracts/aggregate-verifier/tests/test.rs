use aggregate_verifier::contract::*;
use aggregate_verifier::msg::{ExecuteMsg, InstantiateMsg};
use cosmwasm_std::from_binary;
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};

use crate::mock::{make_mock_voting_verifier, mark_messages_as_verified};
pub mod mock;
fn generate_messages(count: usize) -> Vec<connection_router::state::Message> {
    let mut msgs = vec![];
    for x in 0..count {
        msgs.push(connection_router::state::Message::new(
            x.to_string().parse().unwrap(),
            "idc".into(),
            "cj-chain".parse().unwrap(),
            "cj-chain-2".parse().unwrap(),
            "idc".into(),
            vec![x as u8, 0, 0, 0].into(),
        ));
    }
    msgs
}

fn convert_messages(
    msgs: &Vec<connection_router::state::Message>,
) -> Vec<connection_router::msg::Message> {
    msgs.into_iter().map(|m| m.clone().into()).collect()
}

#[test]
fn verify_messages_empty() {
    let mut app = App::default();
    let voting_verifier_address = make_mock_voting_verifier(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
    let code_id = app.store_code(Box::new(code));

    let verifier_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                voting_verifier_address: voting_verifier_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            verifier_address.clone(),
            &ExecuteMsg::VerifyMessages { messages: vec![] },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, bool)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(ret, vec![]);
}

#[test]
fn verify_messages_not_verified() {
    let mut app = App::default();
    let voting_verifier_address = make_mock_voting_verifier(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
    let code_id = app.store_code(Box::new(code));

    let verifier_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                voting_verifier_address: voting_verifier_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(10);
    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            verifier_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, bool)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), false))
            .collect::<Vec<(String, bool)>>()
    );
}

#[test]
fn verify_messages_verified() {
    let mut app = App::default();
    let voting_verifier_address = make_mock_voting_verifier(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
    let code_id = app.store_code(Box::new(code));

    let verifier_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                voting_verifier_address: voting_verifier_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(10);
    mark_messages_as_verified(&mut app, voting_verifier_address, convert_messages(&msgs));

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            verifier_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, bool)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| (m.id(), true))
            .collect::<Vec<(String, bool)>>()
    );
}

#[test]
fn verify_messages_mixed_status() {
    let mut app = App::default();
    let voting_verifier_address = make_mock_voting_verifier(&mut app);

    let code = ContractWrapper::new(execute, instantiate, query).with_reply(reply);
    let code_id = app.store_code(Box::new(code));

    let verifier_address = app
        .instantiate_contract(
            code_id,
            Addr::unchecked("gateway"),
            &InstantiateMsg {
                voting_verifier_address: voting_verifier_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(10);
    let (verified, _) = msgs.split_at(5);
    mark_messages_as_verified(
        &mut app,
        voting_verifier_address,
        convert_messages(&verified.to_vec()),
    );

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            verifier_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: convert_messages(&msgs),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(String, bool)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|m| if verified.iter().find(|m2| *m2 == m).is_some() {
                (m.id(), true)
            } else {
                (m.id(), false)
            })
            .collect::<Vec<(String, bool)>>()
    );
}

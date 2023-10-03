use aggregate_verifier::contract::*;
use aggregate_verifier::msg::{ExecuteMsg, InstantiateMsg};
use connection_router::state::{CrossChainId, Message, ID_SEPARATOR};
use cosmwasm_std::from_binary;
use cosmwasm_std::Addr;
use cw_multi_test::{App, ContractWrapper, Executor};

use crate::mock::{make_mock_voting_verifier, mark_messages_as_verified};
pub mod mock;

fn generate_messages(count: usize) -> Vec<Message> {
    let mut msgs = vec![];
    for x in 0..count {
        let src_chain = "mock-chain";
        let id = format!("tx_hash{}{}", ID_SEPARATOR, x);
        msgs.push(Message {
            cc_id: CrossChainId {
                chain: src_chain.parse().unwrap(),
                id: id.parse().unwrap(),
            },
            destination_address: "idc".parse().unwrap(),
            destination_chain: "mock-chain-2".parse().unwrap(),
            source_address: "idc".parse().unwrap(),
            payload_hash: vec![x as u8, 0, 0, 0].into(),
        });
    }
    msgs
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
                verifier_address: voting_verifier_address.to_string(),
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
    let ret: Vec<(CrossChainId, bool)> = from_binary(&res.data.unwrap()).unwrap();
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
                verifier_address: voting_verifier_address.to_string(),
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
                messages: msgs.clone(),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(CrossChainId, bool)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| (msg.cc_id.clone(), false))
            .collect::<Vec<(CrossChainId, bool)>>()
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
                verifier_address: voting_verifier_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(10);
    mark_messages_as_verified(&mut app, voting_verifier_address, msgs.clone());

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            verifier_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: msgs.clone(),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(CrossChainId, bool)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| (msg.cc_id.clone(), true))
            .collect::<Vec<(CrossChainId, bool)>>()
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
                verifier_address: voting_verifier_address.to_string(),
            },
            &[],
            "Contract",
            None,
        )
        .unwrap();

    let msgs = generate_messages(10);
    let (verified, _) = msgs.split_at(5);
    mark_messages_as_verified(&mut app, voting_verifier_address, verified.to_vec());

    let res = app
        .execute_contract(
            Addr::unchecked("relayer"),
            verifier_address.clone(),
            &ExecuteMsg::VerifyMessages {
                messages: msgs.clone(),
            },
            &[],
        )
        .unwrap();
    let ret: Vec<(CrossChainId, bool)> = from_binary(&res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        msgs.iter()
            .map(|msg| {
                if verified
                    .iter()
                    .find(|verified_msg| *verified_msg == msg)
                    .is_some()
                {
                    (msg.cc_id.clone(), true)
                } else {
                    (msg.cc_id.clone(), false)
                }
            })
            .collect::<Vec<(CrossChainId, bool)>>()
    );
}

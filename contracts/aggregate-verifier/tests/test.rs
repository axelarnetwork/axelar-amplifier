use aggregate_verifier::msg::ExecuteMsg;
use axelar_wasm_std::VerificationStatus;
use connection_router_api::{CrossChainId, Message};
use cosmwasm_std::from_json;
use cosmwasm_std::Addr;
use cw_multi_test::App;

use integration_tests::contract::Contract;

use crate::mock::{make_mock_voting_verifier, mark_messages_as_verified};

pub mod mock;
mod test_utils;

fn generate_messages(count: usize) -> Vec<Message> {
    let mut msgs = vec![];
    for x in 0..count {
        let src_chain = "mock-chain";
        let id = format!("tx_hash{}", x);
        msgs.push(Message {
            cc_id: CrossChainId {
                chain: src_chain.parse().unwrap(),
                id: id.parse().unwrap(),
            },
            destination_address: "idc".parse().unwrap(),
            destination_chain: "mock-chain-2".parse().unwrap(),
            source_address: "idc".parse().unwrap(),
            payload_hash: [x as u8; 32],
        });
    }
    msgs
}

#[test]
fn verify_messages_empty() {
    let mut app = App::default();
    let voting_verifier_address = make_mock_voting_verifier(&mut app);

    let aggregate_verifier = test_utils::AggregateVerifierContract::instantiate_contract(
        &mut app,
        voting_verifier_address.clone(),
    );

    let res = aggregate_verifier
        .execute(
            &mut app,
            Addr::unchecked("relayer"),
            &ExecuteMsg::VerifyMessages { messages: vec![] },
        )
        .unwrap();
    let ret: Vec<(CrossChainId, VerificationStatus)> = from_json(res.data.unwrap()).unwrap();
    assert_eq!(ret, vec![]);
}

#[test]
fn verify_messages_not_verified() {
    let mut app = App::default();
    let voting_verifier_address = make_mock_voting_verifier(&mut app);

    let aggregate_verifier = test_utils::AggregateVerifierContract::instantiate_contract(
        &mut app,
        voting_verifier_address.clone(),
    );

    let messages = generate_messages(10);
    let res = aggregate_verifier
        .execute(
            &mut app,
            Addr::unchecked("relayer"),
            &ExecuteMsg::VerifyMessages {
                messages: messages.clone(),
            },
        )
        .unwrap();
    let ret: Vec<(CrossChainId, VerificationStatus)> = from_json(res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        messages
            .iter()
            .map(|msg| (msg.cc_id.clone(), VerificationStatus::None))
            .collect::<Vec<(_, _)>>()
    );
}

#[test]
fn verify_messages_verified() {
    let mut app = App::default();
    let voting_verifier_address = make_mock_voting_verifier(&mut app);

    let aggregate_verifier = test_utils::AggregateVerifierContract::instantiate_contract(
        &mut app,
        voting_verifier_address.clone(),
    );

    let messages = generate_messages(10);
    mark_messages_as_verified(&mut app, voting_verifier_address, messages.clone());

    let res = aggregate_verifier
        .execute(
            &mut app,
            Addr::unchecked("relayer"),
            &ExecuteMsg::VerifyMessages {
                messages: messages.clone(),
            },
        )
        .unwrap();
    let ret: Vec<(CrossChainId, VerificationStatus)> = from_json(res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        messages
            .iter()
            .map(|msg| (msg.cc_id.clone(), VerificationStatus::SucceededOnChain))
            .collect::<Vec<(_, _)>>()
    );
}

#[test]
fn verify_messages_mixed_status() {
    let mut app = App::default();
    let voting_verifier_address = make_mock_voting_verifier(&mut app);

    let aggregate_verifier = test_utils::AggregateVerifierContract::instantiate_contract(
        &mut app,
        voting_verifier_address.clone(),
    );

    let messages = generate_messages(10);
    let (verified, _) = messages.split_at(5);
    mark_messages_as_verified(&mut app, voting_verifier_address, verified.to_vec());

    let res = aggregate_verifier
        .execute(
            &mut app,
            Addr::unchecked("relayer"),
            &ExecuteMsg::VerifyMessages {
                messages: messages.clone(),
            },
        )
        .unwrap();
    let ret: Vec<(CrossChainId, VerificationStatus)> = from_json(res.data.unwrap()).unwrap();
    assert_eq!(
        ret,
        messages
            .iter()
            .map(|msg| {
                if verified.iter().any(|verified_msg| verified_msg == msg) {
                    (msg.cc_id.clone(), VerificationStatus::SucceededOnChain)
                } else {
                    (msg.cc_id.clone(), VerificationStatus::None)
                }
            })
            .collect::<Vec<(_, _)>>()
    );
}

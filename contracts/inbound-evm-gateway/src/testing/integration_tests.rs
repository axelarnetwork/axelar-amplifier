use auth_vote::{state::PollState, VoteResult};
use cosmwasm_std::{Addr, Attribute, Uint256, Uint64};

use crate::testing::utils::setup::default_instantiation_message;

use super::utils::{
    executes::{finalize_actions, post_worker_reply, request_worker_action},
    setup::{setup_test_case, WORKERS},
};

#[test]
fn test_request_worker_action() {
    let (mut app, service_addr, _, _) = setup_test_case(None, None, None, None);

    let from_nonce = Uint256::from(0u8);
    let to_nonce = Uint256::from(5u8);
    let source_chain = default_instantiation_message()
        .inbound_settings
        .source_chain_name;
    let poll_id = Uint64::one();

    let res = request_worker_action(&mut app, service_addr.clone(), from_nonce, to_nonce).unwrap();

    let event = res
        .events
        .iter()
        .find(|event| event.ty == "wasm-ConfirmGatewayTxStarted");

    assert!(event.is_some());

    let attributes = &event.unwrap().attributes;
    assert!(attributes.contains(&Attribute::new("poll_id", poll_id)));
    assert!(attributes.contains(&Attribute::new("source_chain", source_chain)));
    assert!(attributes.contains(&Attribute::new("from_nonce", from_nonce)));
    assert!(attributes.contains(&Attribute::new("to_nonce", to_nonce)));
}

#[test]
fn test_post_worker_reply() {
    let (mut app, service_addr, _, _) = setup_test_case(None, None, None, None);

    let from_nonce = Uint256::from(0u8);
    let to_nonce = Uint256::from(5u8);
    let poll_id = Uint64::one();
    let calls_hash = [0u8; 32];

    request_worker_action(&mut app, service_addr.clone(), from_nonce, to_nonce).unwrap();

    let res = post_worker_reply(&mut app, WORKERS[0], service_addr, poll_id, calls_hash).unwrap();
    let event = res.events.iter().find(|event| event.ty == "wasm-Voted");

    assert!(event.is_some());

    let attributes = &event.unwrap().attributes;
    assert!(attributes.contains(&Attribute::new("poll_id", poll_id)));
    assert!(attributes.contains(&Attribute::new("voter", Addr::unchecked(WORKERS[0]))));
    assert!(attributes.contains(&Attribute::new(
        "vote_result",
        VoteResult::VoteInTime.to_string()
    )));
    assert!(attributes.contains(&Attribute::new("state", PollState::Pending.to_string())));
}

#[test]
fn test_finalize_actions() {
    let (mut app, service_addr, _, _) = setup_test_case(None, None, None, None);

    let from_nonce = Uint256::from(0u8);
    let to_nonce = Uint256::from(5u8);
    let source_chain = default_instantiation_message()
        .inbound_settings
        .source_chain_name;
    let poll_id = Uint64::one();
    let calls_hash = [0u8; 32];

    request_worker_action(&mut app, service_addr.clone(), from_nonce, to_nonce).unwrap();

    for worker in WORKERS {
        post_worker_reply(&mut app, worker, service_addr.clone(), poll_id, calls_hash).unwrap();
    }

    app.update_block(|block| {
        block.time = block.time.plus_seconds(25);
        block.height += 5;
    });

    let res = finalize_actions(&mut app, service_addr).unwrap();
    let event = res
        .events
        .iter()
        .find(|event| event.ty == "wasm-PollCompleted");

    assert!(event.is_some());

    let attributes = &event.unwrap().attributes;
    assert!(attributes.contains(&Attribute::new("poll_id", poll_id)));
    assert!(attributes.contains(&Attribute::new("from_nonce", from_nonce)));
    assert!(attributes.contains(&Attribute::new("to_nonce", to_nonce)));
    assert!(attributes.contains(&Attribute::new("chain", source_chain)));
}

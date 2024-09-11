use std::str::FromStr;

use assert_ok::assert_ok;
use axelar_wasm_std::assert_err_contains;
use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::response::inspect_response_msg;
use axelarnet_gateway::contract::{self, ExecuteError};
use axelarnet_gateway::msg::ExecuteMsg;
use axelarnet_gateway::StateError;
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use cosmwasm_std::{DepsMut, HexBinary, Response};
use router_api::msg::ExecuteMsg as RouterExecuteMsg;
use router_api::{Address, ChainName, CrossChainId, Message};

use crate::utils::messages;

mod utils;

#[test]
fn execute_message_when_not_approved_fails() {
    let mut deps = mock_dependencies();

    let cc_id = CrossChainId::new("source-chain", "hash-index").unwrap();
    let payload = vec![1, 2, 3].into();

    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_err_contains!(
        utils::execute_payload(deps.as_mut(), cc_id, payload),
        StateError,
        StateError::MessageNotApproved(..)
    );
}

#[test]
fn execute_approved_message_when_already_executed_fails() {
    let mut deps = mock_dependencies();

    let payload: HexBinary = vec![1, 2, 3].into();
    let msg = messages::dummy_from_router(&payload);
    let cc_id = msg.cc_id.clone();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    utils::route_from_router(deps.as_mut(), vec![msg]).unwrap();
    utils::execute_payload(deps.as_mut(), cc_id.clone(), payload.clone()).unwrap();

    assert_err_contains!(
        utils::execute_payload(deps.as_mut(), cc_id, payload),
        StateError,
        StateError::MessageAlreadyExecuted(..)
    );
}

#[test]
fn execute_approved_message_when_payload_mismatch_fails() {
    let mut deps = mock_dependencies();

    let payload: Vec<u8> = vec![1, 2, 3];
    let mismatched_payload = vec![4, 5, 6].into();
    let msg = messages::dummy_from_router(&payload);
    let cc_id = msg.cc_id.clone();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    utils::route_from_router(deps.as_mut(), vec![msg]).unwrap();

    assert_err_contains!(
        utils::execute_payload(deps.as_mut(), cc_id, mismatched_payload),
        StateError,
        StateError::PayloadHashMismatch
    );
}

#[test]
fn execute_approved_message_once_returns_correct_message() {
    let mut deps = mock_dependencies();

    let payload = vec![1, 2, 3].into();
    let msg = messages::dummy_from_router(&payload);
    let cc_id = msg.cc_id.clone();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    utils::route_from_router(deps.as_mut(), vec![msg]).unwrap();

    let response = assert_ok!(utils::execute_payload(deps.as_mut(), cc_id, payload));
    let msg = assert_ok!(inspect_response_msg::<utils::ExecuteMsg>(response));
    goldie::assert_json!(msg)
}

#[test]
fn execute_approved_message_once_returns_correct_events() {
    let mut deps = mock_dependencies();

    let payload = vec![1, 2, 3].into();
    let msg = messages::dummy_from_router(&payload);
    let cc_id = msg.cc_id.clone();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    utils::route_from_router(deps.as_mut(), vec![msg]).unwrap();

    let response = assert_ok!(utils::execute_payload(deps.as_mut(), cc_id, payload));
    goldie::assert_json!(response.events)
}

#[test]
fn route_from_router_with_destination_chain_not_matching_contract_fails() {
    let mut deps = mock_dependencies();

    let msg = messages::dummy_from_router(&[1, 2, 3]);
    let msg_with_wrong_destination = Message {
        destination_chain: "wrong-chain".parse().unwrap(),
        ..msg
    };

    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_err_contains!(
        utils::route_from_router(deps.as_mut(), vec![msg_with_wrong_destination]),
        ExecuteError,
        ExecuteError::InvalidDestination { .. }
    );
}

#[test]
fn route_from_router_same_message_multiple_times_succeeds() {
    let mut deps = mock_dependencies();

    let msgs = vec![messages::dummy_from_router(&[1, 2, 3])];

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let response = assert_ok!(utils::route_from_router(deps.as_mut(), msgs));
    goldie::assert_json!(response);
}

#[test]
fn route_from_router_multiple_times_with_data_mismatch_fails() {
    let mut deps = mock_dependencies();

    let mut msgs = vec![messages::dummy_from_router(&[1, 2, 3])];

    utils::instantiate_contract(deps.as_mut()).unwrap();
    utils::route_from_router(deps.as_mut(), msgs.clone()).unwrap();

    msgs[0].source_address = "wrong-address".parse().unwrap();

    assert_err_contains!(
        utils::route_from_router(deps.as_mut(), msgs),
        StateError,
        StateError::MessageMismatch(..)
    );
}

#[test]
fn route_to_router_without_contract_call_ignores_message() {
    let mut deps = mock_dependencies();

    let msg = messages::dummy_to_router(&vec![1, 2, 3]);

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let response = assert_ok!(route_to_router(deps.as_mut(), vec![msg]));
    assert_eq!(response.messages.len(), 0);
}

#[test]
fn route_to_router_after_contract_call_with_tempered_data_fails() {
    let mut deps = mock_dependencies();

    let destination_chain = "destination-chain".parse().unwrap();
    let destination_address = "destination-address".parse().unwrap();
    let payload = vec![1, 2, 3].into();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    let response = utils::call_contract(
        deps.as_mut(),
        destination_chain,
        destination_address,
        payload,
    )
    .unwrap();

    let RouterExecuteMsg::RouteMessages(mut msgs) = inspect_response_msg(response).unwrap() else {
        panic!("pattern must match")
    };
    msgs[0].destination_chain = "wrong-chain".parse().unwrap();

    assert_err_contains!(
        route_to_router(deps.as_mut(), msgs),
        ExecuteError,
        ExecuteError::MessageMismatch(..)
    );
}

#[test]
fn route_to_router_after_contract_call_succeeds_multiple_times() {
    let mut deps = mock_dependencies();

    let destination_chain = "destination-chain".parse().unwrap();
    let destination_address = "destination-address".parse().unwrap();
    let payload = vec![1, 2, 3].into();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    let response = utils::call_contract(
        deps.as_mut(),
        destination_chain,
        destination_address,
        payload,
    )
    .unwrap();

    let RouterExecuteMsg::RouteMessages(msgs) = inspect_response_msg(response).unwrap() else {
        panic!("pattern must match")
    };

    for _ in 0..10 {
        let response = assert_ok!(route_to_router(deps.as_mut(), msgs.clone()));
        let msg = assert_ok!(inspect_response_msg::<RouterExecuteMsg>(response));
        goldie::assert_json!(msg);
    }
}

#[test]
fn route_to_router_after_contract_call_ignores_duplicates() {
    let mut deps = mock_dependencies();

    let destination_chain = "destination-chain".parse().unwrap();
    let destination_address = "destination-address".parse().unwrap();
    let payload = vec![1, 2, 3].into();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    let response = utils::call_contract(
        deps.as_mut(),
        destination_chain,
        destination_address,
        payload,
    )
    .unwrap();

    let RouterExecuteMsg::RouteMessages(mut msgs) = inspect_response_msg(response).unwrap() else {
        panic!("pattern must match")
    };

    msgs.append(&mut msgs.clone());
    msgs.append(&mut msgs.clone());
    assert_eq!(msgs.len(), 4);

    let response = assert_ok!(route_to_router(deps.as_mut(), msgs));
    let msg = assert_ok!(inspect_response_msg::<RouterExecuteMsg>(response));
    goldie::assert_json!(msg);
}

#[test]
fn contract_call_returns_correct_message() {
    let mut deps = mock_dependencies();

    let destination_chain = "destination-chain".parse().unwrap();
    let destination_address = "destination-address".parse().unwrap();
    let payload = vec![1, 2, 3].into();

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let response = assert_ok!(utils::call_contract(
        deps.as_mut(),
        destination_chain,
        destination_address,
        payload,
    ));
    let msg = assert_ok!(inspect_response_msg::<RouterExecuteMsg>(response));
    goldie::assert_json!(msg)
}

#[test]
fn contract_call_returns_correct_events() {
    let mut deps = mock_dependencies();

    let destination_chain = "destination-chain".parse().unwrap();
    let destination_address = "destination-address".parse().unwrap();
    let payload = vec![1, 2, 3].into();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    let response = assert_ok!(utils::call_contract(
        deps.as_mut(),
        destination_chain,
        destination_address,
        payload,
    ));
    goldie::assert_json!(response.events)
}

#[test]
fn contract_call_multiple_times_results_in_different_messages() {
    let mut deps = mock_dependencies();

    let destination_chain = ChainName::from_str("destination-chain").unwrap();
    let destination_address = Address::from_str("destination-address").unwrap();
    let payload = HexBinary::from(vec![1, 2, 3]);

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let response1 = assert_ok!(utils::call_contract(
        deps.as_mut(),
        destination_chain.clone(),
        destination_address.clone(),
        payload.clone(),
    ));
    let response2 = assert_ok!(utils::call_contract(
        deps.as_mut(),
        destination_chain,
        destination_address,
        payload,
    ));

    assert_ne!(response1.messages, response2.messages);
}

fn route_to_router(deps: DepsMut, msgs: Vec<Message>) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        ExecuteMsg::RouteMessages(msgs),
    )
}

use std::str::FromStr;

use axelar_wasm_std::error::ContractError;
use axelarnet_gateway::contract;
use axelarnet_gateway::msg::ExecuteMsg;
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use cosmwasm_std::{DepsMut, HexBinary, Response};
use router_api::msg::ExecuteMsg as RouterExecuteMsg;
use router_api::{Address, ChainName, CrossChainId, Message};

use crate::utils::messages;
use crate::utils::messages::inspect_response_msg;

mod utils;

#[test]
fn execute_message_when_not_approved_fails() {
    let mut deps = mock_dependencies();

    let cc_id = CrossChainId::new("source-chain", "hash-index").unwrap();
    let payload = vec![1, 2, 3].into();

    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert!(utils::execute_payload(deps.as_mut(), cc_id, payload).is_err());
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

    assert!(utils::execute_payload(deps.as_mut(), cc_id, payload).is_err());
}

#[test]
fn execute_approved_message_when_payload_mismatch_fails() {
    let mut deps = mock_dependencies();

    let payload = vec![1, 2, 3];
    let mismatched_payload = vec![4, 5, 6].into();
    let msg = messages::dummy_from_router(&payload);
    let cc_id = msg.cc_id.clone();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    utils::route_from_router(deps.as_mut(), vec![msg]).unwrap();

    assert!(utils::execute_payload(deps.as_mut(), cc_id, mismatched_payload).is_err());
}

#[test]
fn execute_approved_message_once_returns_correct_message() {
    let mut deps = mock_dependencies();

    let payload = vec![1, 2, 3].into();
    let msg = messages::dummy_from_router(&payload);
    let cc_id = msg.cc_id.clone();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    utils::route_from_router(deps.as_mut(), vec![msg]).unwrap();

    let response = utils::execute_payload(deps.as_mut(), cc_id, payload);
    assert!(response.is_ok());

    let msg = inspect_response_msg::<utils::ExecuteMsg>(response.unwrap());
    assert!(msg.is_ok());
    goldie::assert_json!(msg.unwrap())
}

#[test]
fn execute_approved_message_once_returns_correct_events() {
    let mut deps = mock_dependencies();

    let payload = vec![1, 2, 3].into();
    let msg = messages::dummy_from_router(&payload);
    let cc_id = msg.cc_id.clone();

    utils::instantiate_contract(deps.as_mut()).unwrap();
    utils::route_from_router(deps.as_mut(), vec![msg]).unwrap();

    let response = utils::execute_payload(deps.as_mut(), cc_id, payload);
    assert!(response.is_ok());

    goldie::assert_json!(response.unwrap().events)
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

    assert!(utils::route_from_router(deps.as_mut(), vec![msg_with_wrong_destination]).is_err());
}

#[test]
fn route_from_router_same_message_multiple_times_succeeds() {
    let mut deps = mock_dependencies();

    let msgs = vec![messages::dummy_from_router(&[1, 2, 3])];

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let response = utils::route_from_router(deps.as_mut(), msgs);
    assert!(response.is_ok());
    goldie::assert_json!(response.unwrap());
}

#[test]
fn route_from_router_multiple_times_with_data_mismatch_fails() {
    let mut deps = mock_dependencies();

    let mut msgs = vec![messages::dummy_from_router(&[1, 2, 3])];

    utils::instantiate_contract(deps.as_mut()).unwrap();
    utils::route_from_router(deps.as_mut(), msgs.clone()).unwrap();

    msgs[0].source_address = "wrong-address".parse().unwrap();

    assert!(utils::route_from_router(deps.as_mut(), msgs).is_err());
}

#[test]
fn route_to_router_without_contract_call_ignores_message() {
    let mut deps = mock_dependencies();

    let msg = messages::dummy_to_router(&vec![1, 2, 3]);

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let response = route_to_router(deps.as_mut(), vec![msg]);
    assert!(response.is_ok());
    assert_eq!(response.unwrap().messages.len(), 0);
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

    assert!(route_to_router(deps.as_mut(), msgs.clone()).is_err());
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
        let response = route_to_router(deps.as_mut(), msgs.clone());
        assert!(response.is_ok());
        let msg = inspect_response_msg::<RouterExecuteMsg>(response.unwrap());
        assert!(msg.is_ok());
        goldie::assert_json!(msg.unwrap());
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

    let response = route_to_router(deps.as_mut(), msgs);
    assert!(response.is_ok());
    let msg = inspect_response_msg::<RouterExecuteMsg>(response.unwrap());
    assert!(msg.is_ok());
    goldie::assert_json!(msg.unwrap());
}

#[test]
fn contract_call_returns_correct_message() {
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
    );

    assert!(response.is_ok());

    let msg = inspect_response_msg::<RouterExecuteMsg>(response.unwrap());
    assert!(msg.is_ok());
    goldie::assert_json!(msg.unwrap())
}

#[test]
fn contract_call_returns_correct_events() {
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
    );

    assert!(response.is_ok());
    goldie::assert_json!(response.unwrap().events)
}

#[test]
fn contract_call_multiple_times_results_in_different_messages() {
    let mut deps = mock_dependencies();

    let destination_chain = ChainName::from_str("destination-chain").unwrap();
    let destination_address = Address::from_str("destination-address").unwrap();
    let payload = HexBinary::from(vec![1, 2, 3]);

    utils::instantiate_contract(deps.as_mut()).unwrap();
    let response1 = utils::call_contract(
        deps.as_mut(),
        destination_chain.clone(),
        destination_address.clone(),
        payload.clone(),
    );

    let response2 = utils::call_contract(
        deps.as_mut(),
        destination_chain,
        destination_address,
        payload,
    );

    assert!(response1.is_ok());
    assert!(response2.is_ok());
    assert_ne!(response1.unwrap().messages, response2.unwrap().messages);
}

fn route_to_router(deps: DepsMut, msgs: Vec<Message>) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        ExecuteMsg::RouteMessages(msgs),
    )
}

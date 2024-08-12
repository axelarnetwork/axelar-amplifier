use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::iter;

use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::{err_contains, VerificationStatus};
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info, MockQuerier};
#[cfg(not(feature = "generate_golden_files"))]
use cosmwasm_std::Response;
use cosmwasm_std::{
    from_json, to_json_binary, Addr, ContractResult, DepsMut, QuerierResult, WasmQuery,
};
use gateway::contract::*;
use gateway::msg::InstantiateMsg;
use gateway_api::msg::{ExecuteMsg, QueryMsg};
use itertools::Itertools;
use rand::{thread_rng, Rng};
use router_api::{CrossChainId, Message};
use serde::Serialize;
use voting_verifier::msg::MessageStatus;

#[test]
fn instantiate_works() {
    let result = instantiate(
        mock_dependencies().as_mut(),
        mock_env(),
        mock_info("sender", &[]),
        InstantiateMsg {
            verifier_address: Addr::unchecked("verifier").into_string(),
            router_address: Addr::unchecked("router").into_string(),
        },
    );

    assert!(result.is_ok());
}

#[test]
fn successful_verify() {
    let (test_cases, handler) = test_cases_for_correct_verifier();

    let mut responses = vec![];
    for msgs in test_cases {
        let mut deps = mock_dependencies();
        update_query_handler(&mut deps.querier, handler.clone());

        instantiate_contract(deps.as_mut(), "verifier", "router");

        // check verification is idempotent
        let response = iter::repeat(
            execute(
                deps.as_mut(),
                mock_env(),
                mock_info("sender", &[]),
                ExecuteMsg::VerifyMessages(msgs.clone()),
            )
            .unwrap(),
        )
        .take(10)
        .dedup()
        .collect::<Vec<_>>();

        assert_eq!(response.len(), 1);

        responses.push(response[0].clone());
    }

    let golden_file = "tests/test_verify.json";
    #[cfg(feature = "generate_golden_files")]
    {
        let f = File::create(golden_file).unwrap();
        serde_json::to_writer_pretty(f, &responses).unwrap();
    }
    #[cfg(not(feature = "generate_golden_files"))]
    {
        let f = File::open(golden_file).unwrap();
        let expected_responses: Vec<Response> = serde_json::from_reader(f).unwrap();
        assert_eq!(
            serde_json::to_string_pretty(&responses).unwrap(),
            serde_json::to_string_pretty(&expected_responses).unwrap()
        );
    }
}

#[test]
fn successful_route_incoming() {
    let (test_cases, handler) = test_cases_for_correct_verifier();

    let mut responses = vec![];
    for msgs in test_cases {
        let mut deps = mock_dependencies();
        update_query_handler(&mut deps.querier, handler.clone());

        instantiate_contract(deps.as_mut(), "verifier", "router");

        // check routing of incoming messages is idempotent
        let response = iter::repeat(
            execute(
                deps.as_mut(),
                mock_env(),
                mock_info("sender", &[]),
                ExecuteMsg::RouteMessages(msgs.clone()),
            )
            .unwrap(),
        )
        .take(2)
        .dedup()
        .collect::<Vec<_>>();

        assert_eq!(response.len(), 1);

        responses.push(response[0].clone());
    }

    let golden_file = "tests/test_route_incoming.json";
    #[cfg(feature = "generate_golden_files")]
    {
        let f = File::create(golden_file).unwrap();
        serde_json::to_writer_pretty(f, &responses).unwrap();
    }
    #[cfg(not(feature = "generate_golden_files"))]
    {
        let f = File::open(golden_file).unwrap();
        let expected_responses: Vec<Response> = serde_json::from_reader(f).unwrap();
        assert_eq!(responses, expected_responses);
    }
}

#[test]
fn successful_route_outgoing() {
    // outgoing routing should not check the verifier, so we ensure this by not mocking it.
    // If it was called it would return an error
    let (test_cases, _) = test_cases_for_correct_verifier();

    let mut responses = vec![];
    for msgs in test_cases {
        let mut deps = mock_dependencies();

        let router = "router";
        instantiate_contract(deps.as_mut(), "verifier", router);

        let query_msg =
            QueryMsg::OutgoingMessages(msgs.iter().map(|msg| msg.cc_id.clone()).collect());

        // check no messages are outgoing
        let query_response = query(deps.as_ref(), mock_env(), query_msg.clone());
        if msgs.is_empty() {
            assert_eq!(
                query_response.unwrap(),
                to_json_binary::<Vec<CrossChainId>>(&vec![]).unwrap()
            )
        } else {
            assert!(query_response.is_err());
        }

        // check routing of outgoing messages is idempotent
        let response = iter::repeat(
            execute(
                deps.as_mut(),
                mock_env(),
                mock_info(router, &[]), // execute with router as sender
                ExecuteMsg::RouteMessages(msgs.clone()),
            )
            .unwrap(),
        )
        .take(2)
        .dedup()
        .collect::<Vec<_>>();

        assert_eq!(response.len(), 1);

        responses.push(response[0].clone());

        // check all outgoing messages are stored because the router (sender) is implicitly trusted
        iter::repeat(query(deps.as_ref(), mock_env().clone(), query_msg).unwrap())
            .take(2)
            .for_each(|response| assert_eq!(response, to_json_binary(&msgs).unwrap()));
    }

    let golden_file = "tests/test_route_outgoing.json";
    #[cfg(feature = "generate_golden_files")]
    {
        let f = File::create(golden_file).unwrap();
        serde_json::to_writer_pretty(f, &responses).unwrap();
    }
    #[cfg(not(feature = "generate_golden_files"))]
    {
        let f = File::open(golden_file).unwrap();
        let expected_responses: Vec<Response> = serde_json::from_reader(f).unwrap();
        assert_eq!(responses, expected_responses);
    }
}

#[test]
fn verify_with_faulty_verifier_fails() {
    // if the mock querier is not overwritten, it will return an error
    let mut deps = mock_dependencies();

    instantiate_contract(deps.as_mut(), "verifier", "router");

    let response = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &[]),
        ExecuteMsg::VerifyMessages(generate_msgs("verifier in unreachable", 10)),
    );

    assert!(response.is_err());
}

#[test]
fn route_incoming_with_faulty_verifier_fails() {
    // if the mock querier is not overwritten, it will return an error
    let mut deps = mock_dependencies();

    instantiate_contract(deps.as_mut(), "verifier", "router");

    let response = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &[]),
        ExecuteMsg::RouteMessages(generate_msgs("verifier in unreachable", 10)),
    );

    assert!(response.is_err());
}

#[test]
fn calls_with_duplicate_ids_should_fail() {
    let (test_cases, handler) = test_cases_for_duplicate_msgs();
    for msgs in test_cases {
        let mut deps = mock_dependencies();
        update_query_handler(&mut deps.querier, handler.clone());

        let router = "router";
        instantiate_contract(deps.as_mut(), "verifier", router);

        let response = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::VerifyMessages(msgs.clone()),
        );
        assert!(response.is_err());

        let response = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::RouteMessages(msgs.clone()),
        );
        assert!(response.is_err());

        let response = execute(
            deps.as_mut(),
            mock_env(),
            mock_info(router, &[]),
            ExecuteMsg::RouteMessages(msgs),
        );
        assert!(response.is_err());
    }
}

#[test]
fn route_duplicate_ids_should_fail() {
    let (test_cases, handler) = test_cases_for_duplicate_msgs();
    for msgs in test_cases {
        let mut deps = mock_dependencies();
        update_query_handler(&mut deps.querier, handler.clone());

        instantiate_contract(deps.as_mut(), "verifier", "router");

        let response = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("sender", &[]),
            ExecuteMsg::RouteMessages(msgs),
        );

        assert!(response.is_err());
    }
}

#[test]
fn reject_reroute_outgoing_message_with_different_contents() {
    let mut msgs = generate_msgs(VerificationStatus::SucceededOnSourceChain, 10);

    let mut deps = mock_dependencies();

    let router = "router";
    instantiate_contract(deps.as_mut(), "verifier", router);

    let response = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(router, &[]),
        ExecuteMsg::RouteMessages(msgs.clone()),
    );
    assert!(response.is_ok());

    // re-route with different payload
    msgs.iter_mut().for_each(|msg| {
        let mut rng = thread_rng();
        msg.payload_hash.iter_mut().for_each(|byte| {
            *byte = rng.gen();
        });
    });
    let response = execute(
        deps.as_mut(),
        mock_env(),
        mock_info(router, &[]),
        ExecuteMsg::RouteMessages(msgs.clone()),
    );
    assert!(response.is_err_and(|err| err_contains!(
        err.report,
        Error,
        Error::RouteOutgoingMessages
    )));
}

fn test_cases_for_correct_verifier() -> (
    Vec<Vec<Message>>,
    impl Fn(voting_verifier::msg::QueryMsg) -> Result<Vec<MessageStatus>, ContractError> + Clone,
) {
    let all_messages = generate_msgs_with_all_statuses(10);
    let status_by_msg = map_status_by_msg(all_messages.clone());
    let handler = correctly_working_verifier_handler(status_by_msg);
    let all_messages = sort_msgs_by_status(all_messages).collect::<Vec<_>>();

    let mut test_cases = vec![];

    // no messages
    test_cases.push(vec![]);
    // one message of each status
    for msgs in all_messages.iter() {
        test_cases.push(msgs.iter().take(1).cloned().collect::<Vec<_>>());
    }
    // multiple messages with same status
    test_cases.append(&mut all_messages.clone());
    // multiple messages with multiple statuses
    test_cases.push(all_messages.into_iter().flatten().collect());

    (test_cases, handler)
}

fn test_cases_for_duplicate_msgs() -> (
    Vec<Vec<Message>>,
    impl Fn(voting_verifier::msg::QueryMsg) -> Result<Vec<MessageStatus>, ContractError> + Clone,
) {
    let all_messages = generate_msgs_with_all_statuses(10);
    let status_by_msg = map_status_by_msg(all_messages.clone());
    let handler = correctly_working_verifier_handler(status_by_msg);
    let all_messages = sort_msgs_by_status(all_messages)
        .flatten()
        .collect::<Vec<_>>();

    let test_cases = vec![
        // one duplicate
        duplicate_msgs(all_messages.clone(), 1),
        // multiple duplicates
        duplicate_msgs(all_messages.clone(), 10),
        // all duplicates
        all_messages
            .clone()
            .into_iter()
            .chain(all_messages.clone())
            .collect::<Vec<_>>(),
    ];

    (test_cases, handler)
}

fn generate_msgs_with_all_statuses(
    count_per_status: u8,
) -> HashMap<VerificationStatus, Vec<Message>> {
    all_statuses()
        .into_iter()
        .map(|status| (status, generate_msgs(status, count_per_status)))
        .collect::<HashMap<VerificationStatus, Vec<Message>>>()
}

fn generate_msgs(namespace: impl Debug, count: u8) -> Vec<Message> {
    (0..count)
        .map(|i| Message {
            cc_id: CrossChainId::new("mock-chain", format!("{:?}{}", namespace, i)).unwrap(),
            destination_address: "idc".parse().unwrap(),
            destination_chain: "mock-chain-2".parse().unwrap(),
            source_address: "idc".parse().unwrap(),
            payload_hash: [i; 32],
        })
        .collect()
}

#[allow(clippy::arithmetic_side_effects)]
fn all_statuses() -> Vec<VerificationStatus> {
    let statuses = vec![
        VerificationStatus::Unknown,
        VerificationStatus::NotFoundOnSourceChain,
        VerificationStatus::FailedToVerify,
        VerificationStatus::InProgress,
        VerificationStatus::SucceededOnSourceChain,
        VerificationStatus::FailedOnSourceChain,
    ];

    // we need to make sure that if the variants change, the tests cover all of them
    let mut status_count: usize = 0;
    for status in &statuses {
        match status {
            VerificationStatus::Unknown
            | VerificationStatus::NotFoundOnSourceChain
            | VerificationStatus::FailedToVerify
            | VerificationStatus::InProgress
            | VerificationStatus::SucceededOnSourceChain
            | VerificationStatus::FailedOnSourceChain => status_count += 1,
        };
    }

    assert_eq!(statuses.len(), status_count);

    statuses
}

fn map_status_by_msg(
    messages_by_status: HashMap<VerificationStatus, Vec<Message>>,
) -> HashMap<Message, VerificationStatus> {
    messages_by_status
        .into_iter()
        .flat_map(|(status, msgs)| msgs.into_iter().map(move |msg| (msg, status)))
        .collect()
}

fn correctly_working_verifier_handler(
    status_by_msg: HashMap<Message, VerificationStatus>,
) -> impl Fn(voting_verifier::msg::QueryMsg) -> Result<Vec<MessageStatus>, ContractError> + Clone + 'static
{
    move |msg: voting_verifier::msg::QueryMsg| -> Result<Vec<MessageStatus>, ContractError> {
        match msg {
            voting_verifier::msg::QueryMsg::MessagesStatus(messages) => Ok(messages
                .into_iter()
                .map(|msg| {
                    MessageStatus::new(
                        msg.clone(),
                        status_by_msg
                            .get(&msg)
                            .copied()
                            .expect("there is a status for every message"),
                    )
                })
                .collect()),
            _ => unimplemented!("unsupported query"),
        }
    }
}

fn update_query_handler<U: Serialize>(
    querier: &mut MockQuerier,
    handler: impl Fn(voting_verifier::msg::QueryMsg) -> Result<U, ContractError> + 'static,
) {
    let handler = move |msg: &WasmQuery| match msg {
        WasmQuery::Smart { msg, .. } => {
            let result = handler(from_json(msg).expect("should not fail to deserialize"))
                .map(|response| to_json_binary(&response).expect("should not fail to serialize"));

            QuerierResult::Ok(ContractResult::from(result))
        }
        _ => unimplemented!("unsupported query"),
    };

    querier.update_wasm(handler)
}

fn instantiate_contract(deps: DepsMut, verifier: &str, router: &str) {
    let response = instantiate(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        InstantiateMsg {
            verifier_address: Addr::unchecked(verifier).into_string(),
            router_address: Addr::unchecked(router).into_string(),
        }
        .clone(),
    );
    assert!(response.is_ok());
}

fn sort_msgs_by_status(
    msgs: HashMap<VerificationStatus, Vec<Message>>,
) -> impl Iterator<Item = Vec<Message>> {
    msgs.into_iter()
        .sorted_by_key(|(status, _)| *status)
        .map(|(_, msgs)| msgs)
}

fn duplicate_msgs(msgs: Vec<Message>, amount: usize) -> Vec<Message> {
    msgs.clone()
        .into_iter()
        .chain(msgs.into_iter().take(amount))
        .collect()
}

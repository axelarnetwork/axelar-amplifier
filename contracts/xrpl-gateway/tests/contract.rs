use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::iter;
use std::marker::PhantomData;
use std::str::FromStr;

use axelar_core_std::nexus;
use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::{err_contains, nonempty, VerificationStatus};
use cosmwasm_std::testing::{
    message_info, mock_dependencies, mock_env, MockApi, MockQuerier, MockQuerierCustomHandlerResult, MockStorage
};
#[cfg(not(feature = "generate_golden_files"))]
use cosmwasm_std::Response;
use cosmwasm_std::{
    from_json, to_json_binary, Api, ContractResult, CustomQuery, Deps, DepsMut, Empty, HexBinary, OwnedDeps, Querier, QuerierResult, QuerierWrapper, Storage, SystemResult, WasmQuery
};
use itertools::Itertools;
use rand::{thread_rng, Rng, RngCore};
use router_api::{ChainName, CrossChainId, Message};
use serde::Serialize;
use serde_json::json;
use sha3::{Digest, Keccak256};
use xrpl_gateway::contract::{execute, instantiate, query};
use xrpl_gateway::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, TokenMetadata};
use xrpl_gateway::state;
use xrpl_types::msg::{WithPayload, XRPLInterchainTransferMessage, XRPLMessage};
use xrpl_types::types::{XRPLAccountId, XRPLPaymentAmount, XRPLTokenOrXrp};
use xrpl_voting_verifier::msg::MessageStatus;

#[test]
fn instantiate_works() {
    let mut deps = mock_dependencies();
    let api = deps.api;

    let result = instantiate(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make("sender"), &[]),
        InstantiateMsg {
            admin_address: api.addr_make("admin").into_string(),
            governance_address: api.addr_make("governance").into_string(),
            verifier_address: api.addr_make("verifier").into_string(),
            router_address: api.addr_make("router").into_string(),
            its_hub_address: api.addr_make("its-hub").into_string(),
            its_hub_chain_name: ChainName::from_str("axelar").unwrap(),
            chain_name: ChainName::from_str("xrpl").unwrap(),
            xrpl_multisig_address: XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo")
                .unwrap(),
        },
    );

    assert!(result.is_ok());
}

#[test]
fn successful_verify() {
    let (test_cases, handler) = test_cases_for_correct_verifier();

    let mut responses = vec![];
    for msgs in test_cases {
        let mut deps = mock_axelar_dependencies();
        instantiate_contract(
            deps.as_default_mut(),
            "verifier",
            "router",
            "its-hub",
            ChainName::from_str("axelar").unwrap(),
        );
        let api = deps.api;
        update_query_handler(&mut deps.querier, handler.clone());

        // check verification is idempotent
        let response = iter::repeat(
            execute(
                deps.as_default_mut(),
                mock_env(),
                message_info(&api.addr_make("sender"), &[]),
                ExecuteMsg::VerifyMessages(msgs),
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
        let mut tx_hash = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut tx_hash);
        let nonce = rand::random();

        let mut deps = mock_axelar_dependencies();
        instantiate_contract(
            deps.as_default_mut(),
            "verifier",
            "router",
            "its-hub",
            ChainName::from_str("axelar").unwrap(),
        );
        let api = deps.api;
        update_query_handler(&mut deps.querier, handler.clone());
        deps.querier = deps.querier.with_custom_handler(axelar_query_handler(tx_hash, nonce));

        execute(
            deps.as_default_mut(),
            mock_env(),
            message_info(&api.addr_make("admin"), &[]),
            ExecuteMsg::DeployRemoteToken {
                xrpl_token: XRPLTokenOrXrp::Xrp,
                destination_chain: "ethereum".parse().unwrap(),
                token_metadata: TokenMetadata {
                    name: "Wrapped XRP".to_string().try_into().unwrap(),
                    symbol: "wXRP".to_string().try_into().unwrap(),
                    minter: None,
                },
            },
        )
        .unwrap();

        // check routing of incoming messages is idempotent
        let response = iter::repeat(
            execute(
                deps.as_default_mut(),
                mock_env(),
                message_info(&api.addr_make("sender"), &[]),
                ExecuteMsg::RouteIncomingMessages(messages_with_payload(msgs.clone())),
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
    let test_cases = outgoing_test_cases_for_correct_verifier();

    let mut responses = vec![];
    for msgs in test_cases {
        let router = "router";
        let mut deps = mock_dependencies();
        instantiate_contract(
            deps.as_mut(),
            "verifier",
            router,
            "its-hub",
            ChainName::from_str("axelar").unwrap(),
        );
        let router_address = deps.api.addr_make(router);

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
                message_info(&router_address, &[]), // execute with router as sender
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
    instantiate_contract(
        deps.as_mut(),
        "verifier",
        "router",
        "its-hub",
        ChainName::from_str("axelar").unwrap(),
    );
    let api = deps.api;

    let msgs = generate_incoming_msgs("verifier in unreachable", 10);
    let response = execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make("sender"), &[]),
        ExecuteMsg::VerifyMessages(msgs),
    );

    assert!(response.is_err());
}

#[test]
fn route_incoming_with_faulty_verifier_fails() {
    // if the mock querier is not overwritten, it will return an error
    let mut deps = mock_dependencies();
    instantiate_contract(
        deps.as_mut(),
        "verifier",
        "router",
        "its-hub",
        ChainName::from_str("axelar").unwrap(),
    );
    let api = deps.api;

    let msgs = generate_incoming_msgs("verifier in unreachable", 10);
    let response = execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make("sender"), &[]),
        ExecuteMsg::RouteIncomingMessages(messages_with_payload(msgs)),
    );

    assert!(response.is_err());
}

#[test]
fn incoming_calls_with_duplicate_ids_should_fail() {
    let (test_cases, handler) = test_cases_for_duplicate_msgs();
    for msgs in test_cases {
        let router = "router";
        let mut deps = mock_axelar_dependencies();
        instantiate_contract(
            deps.as_default_mut(),
            "verifier",
            router,
            "its-hub",
            ChainName::from_str("axelar").unwrap(),
        );
        let api = deps.api;
        update_query_handler(&mut deps.querier, handler.clone());

        let response = execute(
            deps.as_default_mut(),
            mock_env(),
            message_info(&api.addr_make("sender"), &[]),
            ExecuteMsg::VerifyMessages(msgs.clone()),
        );
        assert!(response.is_err());

        let msgs_with_payload = messages_with_payload(msgs.clone());

        let response = execute(
            deps.as_default_mut(),
            mock_env(),
            message_info(&api.addr_make("sender"), &[]),
            ExecuteMsg::RouteIncomingMessages(msgs_with_payload.clone()),
        );
        assert!(response.is_err());

        let response = execute(
            deps.as_default_mut(),
            mock_env(),
            message_info(&api.addr_make(router), &[]),
            ExecuteMsg::RouteIncomingMessages(msgs_with_payload),
        );
        assert!(response.is_err());
    }
}

#[test]
fn outgoing_calls_with_duplicate_ids_should_fail() {
    let test_cases = outgoing_test_cases_for_duplicate_msgs();
    for msgs in test_cases {
        let router = "router";
        let mut deps = mock_dependencies();
        instantiate_contract(
            deps.as_mut(),
            "verifier",
            router,
            "its-hub",
            ChainName::from_str("axelar").unwrap(),
        );
        let api = deps.api;

        let response = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("sender"), &[]),
            ExecuteMsg::RouteMessages(msgs.clone()),
        );
        assert!(response.is_err());

        let response = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make(router), &[]),
            ExecuteMsg::RouteMessages(msgs),
        );
        assert!(response.is_err());
    }
}

#[test]
fn outgoing_route_duplicate_ids_should_fail() {
    let test_cases = outgoing_test_cases_for_duplicate_msgs();
    for msgs in test_cases {
        let mut deps = mock_dependencies();
        instantiate_contract(
            deps.as_mut(),
            "verifier",
            "router",
            "its-hub",
            ChainName::from_str("axelar").unwrap(),
        );
        let api = deps.api;

        let response = execute(
            deps.as_mut(),
            mock_env(),
            message_info(&api.addr_make("sender"), &[]),
            ExecuteMsg::RouteMessages(msgs),
        );

        assert!(response.is_err());
    }
}

#[test]
fn incoming_route_duplicate_ids_should_fail() {
    let (test_cases, handler) = test_cases_for_duplicate_msgs();
    for msgs in test_cases {
        let mut deps = mock_axelar_dependencies();
        instantiate_contract(
            deps.as_default_mut(),
            "verifier",
            "router",
            "its-hub",
            ChainName::from_str("axelar").unwrap(),
        );
        let api = deps.api;
        update_query_handler(&mut deps.querier, handler.clone());

        let response = execute(
            deps.as_default_mut(),
            mock_env(),
            message_info(&api.addr_make("sender"), &[]),
            ExecuteMsg::RouteIncomingMessages(messages_with_payload(msgs)),
        );

        assert!(response.is_err());
    }
}

#[test]
fn reject_reroute_outgoing_message_with_different_contents() {
    let router = "router";
    let its_hub = "its-hub";
    let mut deps = mock_dependencies();
    instantiate_contract(
        deps.as_mut(),
        "verifier",
        router,
        its_hub,
        ChainName::from_str("axelar").unwrap(),
    );
    let api = deps.api;
    let mut msgs = generate_outgoing_msgs(VerificationStatus::SucceededOnSourceChain, 10);

    let response = execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make(router), &[]),
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
        message_info(&api.addr_make(router), &[]),
        ExecuteMsg::RouteMessages(msgs.clone()),
    );
    assert!(response.is_err_and(|err| err_contains!(
        err.report,
        state::Error,
        state::Error::MessageMismatch { .. }
    )));
}

fn test_cases_for_correct_verifier() -> (
    Vec<Vec<XRPLMessage>>,
    impl Fn(xrpl_voting_verifier::msg::QueryMsg) -> Result<Vec<MessageStatus>, ContractError> + Clone,
) {
    let all_messages = generate_incoming_msgs_with_all_statuses(10);
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

fn outgoing_test_cases_for_correct_verifier() -> Vec<Vec<Message>> {
    let all_messages = generate_outgoing_msgs_with_all_statuses(10);
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

    test_cases
}

fn test_cases_for_duplicate_msgs() -> (
    Vec<Vec<XRPLMessage>>,
    impl Fn(xrpl_voting_verifier::msg::QueryMsg) -> Result<Vec<MessageStatus>, ContractError> + Clone,
) {
    let all_messages = generate_incoming_msgs_with_all_statuses(10);
    let status_by_msg = map_status_by_msg(all_messages.clone());
    let handler = correctly_working_verifier_handler(status_by_msg);
    let all_messages = sort_msgs_by_status(all_messages)
        .flatten()
        .collect::<Vec<_>>();

    let test_cases = vec![
        // one duplicate
        duplicate_xrpl_msgs(all_messages.clone(), 1),
        // multiple duplicates
        duplicate_xrpl_msgs(all_messages.clone(), 10),
        // all duplicates
        all_messages
            .clone()
            .into_iter()
            .chain(all_messages.clone())
            .collect::<Vec<_>>(),
    ];

    (test_cases, handler)
}

fn outgoing_test_cases_for_duplicate_msgs() -> Vec<Vec<Message>> {
    let all_messages = generate_outgoing_msgs_with_all_statuses(10);
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

    test_cases
}

fn generate_outgoing_msgs_with_all_statuses(
    count_per_status: u8,
) -> HashMap<VerificationStatus, Vec<Message>> {
    all_statuses()
        .into_iter()
        .map(|status| (status, generate_outgoing_msgs(status, count_per_status)))
        .collect::<HashMap<VerificationStatus, Vec<_>>>()
}

fn generate_incoming_msgs_with_all_statuses(
    count_per_status: u8,
) -> HashMap<VerificationStatus, Vec<XRPLMessage>> {
    all_statuses()
        .into_iter()
        .map(|status| {
            let msgs = generate_incoming_msgs(status, count_per_status);
            (status, msgs)
        })
        .collect::<HashMap<VerificationStatus, Vec<_>>>()
}

fn message_id(id: &str) -> HexTxHash {
    let digest: [u8; 32] = Keccak256::digest(id.as_bytes()).into();
    HexTxHash::new(digest)
}

fn generate_outgoing_msgs(namespace: impl Debug, count: u8) -> Vec<Message> {
    (0..count)
        .map(|i| Message {
            cc_id: CrossChainId::new("axelar", format!("{:?}{}", namespace, i)).unwrap(),
            destination_address: "idc".parse().unwrap(),
            destination_chain: "xrpl".parse().unwrap(),
            source_address: MockApi::default()
                .addr_make("its-hub")
                .as_str()
                .parse()
                .unwrap(),
            payload_hash: [i; 32],
        })
        .collect()
}

fn generate_incoming_msgs(namespace: impl Debug, count: u8) -> Vec<XRPLMessage> {
    (0..count)
        .map(|i| {
            XRPLMessage::InterchainTransferMessage(XRPLInterchainTransferMessage {
                tx_id: message_id(format!("{:?}{}", namespace, i).as_str()),
                amount: XRPLPaymentAmount::Drops(1_000_000),
                destination_address: nonempty::String::try_from("01dc").unwrap(),
                destination_chain: "ethereum".parse().unwrap(),
                source_address: XRPLAccountId::from([i; 20]),
                payload_hash: Some(
                    HexBinary::from_hex(
                        "0c3d72390ac0ce0233c551a3c5278f8625ba996f5985dc8d612a9fc55f1de15a",
                    )
                    .unwrap()
                    .as_slice()
                    .try_into()
                    .unwrap(),
                ),
                gas_fee_amount: XRPLPaymentAmount::Drops(1_000),
            })
        })
        .collect()
}

fn messages_with_payload(msgs: Vec<XRPLMessage>) -> Vec<WithPayload<XRPLMessage>> {
    msgs.into_iter()
        .map(|msg| {
            assert!(
                matches!(msg, XRPLMessage::InterchainTransferMessage(_)),
                "only interchain transfer messages are supported"
            );

            WithPayload::new(
                msg,
                Some(
                    nonempty::HexBinary::try_from(HexBinary::from_hex("0123456789abcdef").unwrap())
                        .unwrap(),
                ),
            )
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
    messages_by_status: HashMap<VerificationStatus, Vec<XRPLMessage>>,
) -> HashMap<XRPLMessage, VerificationStatus> {
    messages_by_status
        .into_iter()
        .flat_map(|(status, msgs)| msgs.into_iter().map(move |msg| (msg, status)))
        .collect()
}

fn correctly_working_verifier_handler(
    status_by_msg: HashMap<XRPLMessage, VerificationStatus>,
) -> impl Fn(xrpl_voting_verifier::msg::QueryMsg) -> Result<Vec<MessageStatus>, ContractError>
       + Clone
       + 'static {
    move |msg: xrpl_voting_verifier::msg::QueryMsg| -> Result<Vec<MessageStatus>, ContractError> {
        match msg {
            xrpl_voting_verifier::msg::QueryMsg::MessagesStatus(messages) => Ok(messages
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
    querier: &mut MockQuerier<AxelarQueryMsg>,
    handler: impl Fn(xrpl_voting_verifier::msg::QueryMsg) -> Result<U, ContractError> + 'static,
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

fn mock_axelar_dependencies(
) -> OwnedDeps<MockStorage, MockApi, MockQuerier<AxelarQueryMsg>, AxelarQueryMsg> {
    OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: MockQuerier::<AxelarQueryMsg>::new(&[("contract", &[])]),
        custom_query_type: PhantomData,
    }
}

fn axelar_query_handler(
    tx_hash: [u8; 32],
    nonce: u32,
) -> impl Fn(&AxelarQueryMsg) -> MockQuerierCustomHandlerResult {
    move |query| {
        let result = match query {
            AxelarQueryMsg::Nexus(nexus_query) => match nexus_query {
                nexus::query::QueryMsg::TxHashAndNonce {} => json!({
                    "tx_hash": tx_hash,
                    "nonce": nonce,
                }),
                _ => unreachable!("unexpected nexus query {:?}", nexus_query),
            },
            _ => unreachable!("unexpected query request {:?}", query),
        }
        .to_string()
        .as_bytes()
        .into();

        SystemResult::Ok(ContractResult::Ok(result))
    }
}

pub trait OwnedDepsExt {
    fn as_default_mut(&mut self) -> DepsMut<Empty>;
    fn as_default_deps(&self) -> Deps<Empty>;
}

impl<S: Storage, A: Api, Q: Querier, C: CustomQuery> OwnedDepsExt for OwnedDeps<S, A, Q, C> {
    fn as_default_mut(&'_ mut self) -> DepsMut<'_, Empty> {
        DepsMut {
            storage: &mut self.storage,
            api: &self.api,
            querier: QuerierWrapper::new(&self.querier),
        }
    }

    fn as_default_deps(&'_ self) -> Deps<'_, Empty> {
        Deps {
            storage: &self.storage,
            api: &self.api,
            querier: QuerierWrapper::new(&self.querier),
        }
    }
}

fn instantiate_contract(
    deps: DepsMut,
    verifier: &str,
    router: &str,
    its_hub: &str,
    its_hub_chain_name: ChainName,
) {
    let api = MockApi::default();
    let response = instantiate(
        deps,
        mock_env(),
        message_info(&api.addr_make("sender"), &[]),
        InstantiateMsg {
            admin_address: api.addr_make("admin").into_string(),
            governance_address: api.addr_make("governance").into_string(),
            verifier_address: api.addr_make(verifier).into_string(),
            router_address: api.addr_make(router).into_string(),
            its_hub_address: api.addr_make(its_hub).into_string(),
            its_hub_chain_name,
            chain_name: ChainName::from_str("xrpl").unwrap(),
            xrpl_multisig_address: XRPLAccountId::from_str("raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo")
                .unwrap(),
        }
        .clone(),
    );

    assert!(response.is_ok());
}

fn sort_msgs_by_status<K, V>(msgs: HashMap<K, V>) -> impl Iterator<Item = V>
where
    K: std::cmp::Ord + Copy,
{
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

fn duplicate_xrpl_msgs(msgs: Vec<XRPLMessage>, amount: usize) -> Vec<XRPLMessage> {
    msgs.clone()
        .into_iter()
        .chain(msgs.into_iter().take(amount))
        .collect()
}

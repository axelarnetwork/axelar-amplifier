#![allow(clippy::unwrap_used)] // Test fixtures and assertions.

use std::collections::HashMap;
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;
use std::str::FromStr;

use axelar_core_std::nexus;
use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::msg_id::HexTxHash;
use axelar_wasm_std::{err_contains, nonempty, permission_control, VerificationStatus};
use cosmwasm_std::testing::{
    message_info, mock_dependencies, mock_env, MockApi, MockQuerier,
    MockQuerierCustomHandlerResult, MockStorage,
};
#[cfg(not(feature = "generate_golden_files"))]
use cosmwasm_std::{
    from_json, to_json_binary, Api, ContractResult, CustomQuery, Deps, DepsMut, Empty, HexBinary,
    OwnedDeps, Querier, QuerierResult, QuerierWrapper, Storage, SystemResult, WasmQuery,
};
use cosmwasm_std::{CosmosMsg, Event, Response, Uint256, WasmMsg};
use interchain_token_service::msg::{TokenInstance, TokenSupply};
use interchain_token_service_std::{
    DeployInterchainToken, HubMessage, LinkToken as ItsLinkToken, Message as ItsMessage,
    RegisterTokenMetadata, TokenId,
};
use itertools::Itertools;
use its_abi_translator::abi::hub_message_abi_decode;
use rand::{thread_rng, Rng, RngCore};
use router_api::{ChainName, ChainNameRaw, CrossChainId, Message};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use sha3::{Digest, Keccak256};
use xrpl_gateway::contract::{execute, instantiate, query, Error};
use xrpl_gateway::msg::{
    CallContract, ExecuteMsg, InstantiateMsg, InterchainTransfer, LinkToken, QueryMsg,
    TokenMetadata,
};
use xrpl_gateway::state;
use xrpl_types::msg::{
    WithPayload, XRPLAddGasMessage, XRPLAddReservesMessage, XRPLCallContractMessage,
    XRPLInterchainTransferMessage, XRPLMessage, XRPLProverMessage,
};
use xrpl_types::types::{
    XRPLAccountId, XRPLCurrency, XRPLPaymentAmount, XRPLToken, XRPLTokenAmount, XRPLTokenOrXrp,
};
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
        let response = iter::repeat_n(
            execute(
                deps.as_default_mut(),
                mock_env(),
                message_info(&api.addr_make("sender"), &[]),
                ExecuteMsg::VerifyMessages(msgs),
            )
            .unwrap(),
            10,
        )
        .dedup()
        .collect::<Vec<_>>();

        assert_eq!(response.len(), 1);

        responses.push(response[0].clone());
    }

    goldie::assert_json!(responses);
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
        deps.querier = deps
            .querier
            .with_custom_handler(axelar_query_handler(tx_hash, nonce));

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
                },
            },
        )
        .unwrap();

        // check routing of incoming messages is idempotent
        let response = iter::repeat_n(
            execute(
                deps.as_default_mut(),
                mock_env(),
                message_info(&api.addr_make("sender"), &[]),
                ExecuteMsg::RouteIncomingMessages(messages_with_payload(msgs.clone())),
            )
            .unwrap(),
            2,
        )
        .dedup()
        .collect::<Vec<_>>();

        assert_eq!(response.len(), 1);

        responses.push(response[0].clone());
    }

    goldie::assert_json!(responses);
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
        let response = iter::repeat_n(
            execute(
                deps.as_mut(),
                mock_env(),
                message_info(&router_address, &[]), // execute with router as sender
                ExecuteMsg::RouteMessages(msgs.clone()),
            )
            .unwrap(),
            2,
        )
        .dedup()
        .collect::<Vec<_>>();

        assert_eq!(response.len(), 1);

        responses.push(response[0].clone());

        // check all outgoing messages are stored because the router (sender) is implicitly trusted
        iter::repeat_n(
            query(deps.as_ref(), mock_env().clone(), query_msg).unwrap(),
            2,
        )
        .for_each(|response| assert_eq!(response, to_json_binary(&msgs).unwrap()));
    }

    goldie::assert_json!(responses);
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

#[allow(clippy::type_complexity)]
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

#[allow(clippy::type_complexity)]
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
                transfer_amount: XRPLPaymentAmount::Drops(999_000),
                gas_fee_amount: XRPLPaymentAmount::Drops(1_000),
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
    fn as_default_mut(&mut self) -> DepsMut<'_, Empty>;
    fn as_default_deps(&self) -> Deps<'_, Empty>;
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

// Fixtures for the token, ITS hub, killswitch and admin flows below.

const VERIFIER: &str = "verifier";
const ROUTER: &str = "router";
const ITS_HUB: &str = "its-hub";
const ADMIN: &str = "admin";
const GOVERNANCE: &str = "governance";
const SENDER: &str = "sender";
const XRPL_MULTISIG: &str = "raNVNWvhUQzFkDDTdEw3roXRJfMJFVJuQo";
const TOKEN_ISSUER: &str = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh";
const XRPL_USER: &str = "rNrjh1KGZk2jBR3wPfAQnoidtFFYQKbQn2";
const DESTINATION_CHAIN: &str = "ethereum";
/// Decimals the mocked ITS hub reports for every token instance.
const HUB_DECIMALS: u8 = 15;

type AxelarDeps = OwnedDeps<MockStorage, MockApi, MockQuerier<AxelarQueryMsg>, AxelarQueryMsg>;

/// Instantiates the gateway with mocked neighbours: the verifier reports `status` for every
/// message, the ITS hub reports `hub_decimals` for every token instance and nexus provides
/// message ids.
fn setup(status: VerificationStatus, hub_decimals: u8) -> AxelarDeps {
    let mut deps = mock_axelar_dependencies();
    instantiate_contract(
        deps.as_default_mut(),
        VERIFIER,
        ROUTER,
        ITS_HUB,
        ChainName::from_str("axelar").unwrap(),
    );

    let verifier = deps.api.addr_make(VERIFIER);
    let its_hub = deps.api.addr_make(ITS_HUB);
    deps.querier
        .update_wasm(move |wasm_query| match wasm_query {
            WasmQuery::Smart { contract_addr, msg } if contract_addr == verifier.as_str() => {
                match from_json(msg).unwrap() {
                    xrpl_voting_verifier::msg::QueryMsg::MessagesStatus(messages) => {
                        let statuses: Vec<MessageStatus> = messages
                            .into_iter()
                            .map(|message| MessageStatus::new(message, status))
                            .collect();
                        query_response(&statuses)
                    }
                    other => panic!("unexpected verifier query {:?}", other),
                }
            }
            WasmQuery::Smart { contract_addr, msg } if contract_addr == its_hub.as_str() => {
                match from_json(msg).unwrap() {
                    interchain_token_service::msg::QueryMsg::TokenInstance { .. } => {
                        query_response(&TokenInstance {
                            supply: TokenSupply::Untracked,
                            decimals: hub_decimals,
                        })
                    }
                    other => panic!("unexpected ITS hub query {:?}", other),
                }
            }
            other => panic!("unexpected query {:?}", other),
        });
    deps.querier = deps
        .querier
        .with_custom_handler(axelar_query_handler([7u8; 32], 1));

    deps
}

fn query_response<T: Serialize>(value: &T) -> QuerierResult {
    SystemResult::Ok(ContractResult::Ok(to_json_binary(value).unwrap()))
}

fn execute_as(
    deps: &mut AxelarDeps,
    sender: &str,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let sender = deps.api.addr_make(sender);
    execute(
        deps.as_default_mut(),
        mock_env(),
        message_info(&sender, &[]),
        msg,
    )
}

fn query_as<T: DeserializeOwned>(deps: &AxelarDeps, msg: QueryMsg) -> Result<T, ContractError> {
    query(deps.as_default_deps(), mock_env(), msg).map(|response| from_json(response).unwrap())
}

fn currency(code: &str) -> XRPLCurrency {
    code.to_string().try_into().unwrap()
}

fn xrpl_multisig() -> XRPLAccountId {
    XRPL_MULTISIG.parse().unwrap()
}

/// A token issued by a third party on XRPL, so local to XRPL.
fn usd_token() -> XRPLToken {
    XRPLToken {
        issuer: TOKEN_ISSUER.parse().unwrap(),
        currency: currency("USD"),
    }
}

/// 1.5 units of `token`, at XRPL's 15 significant digits.
fn one_and_a_half(token: XRPLToken) -> XRPLPaymentAmount {
    XRPLPaymentAmount::Issued(token, XRPLTokenAmount::new(1_500_000_000_000_000, -15))
}

fn register_local_token(deps: &mut AxelarDeps, token: XRPLToken) -> TokenId {
    execute_as(
        deps,
        ADMIN,
        ExecuteMsg::RegisterLocalToken {
            xrpl_token: token.clone(),
        },
    )
    .unwrap();
    query_as(deps, QueryMsg::XrplTokenId(token)).unwrap()
}

fn xrp_token_id(deps: &AxelarDeps) -> TokenId {
    query_as(deps, QueryMsg::XrpTokenId).unwrap()
}

fn payload() -> nonempty::HexBinary {
    nonempty::HexBinary::try_from(HexBinary::from_hex("0123456789abcdef").unwrap()).unwrap()
}

fn keccak(payload: &nonempty::HexBinary) -> [u8; 32] {
    Keccak256::digest(payload.as_ref()).into()
}

fn interchain_transfer_message(
    id: &str,
    amount: XRPLPaymentAmount,
    payload_hash: Option<[u8; 32]>,
) -> XRPLInterchainTransferMessage {
    XRPLInterchainTransferMessage {
        tx_id: message_id(id),
        source_address: XRPL_USER.parse().unwrap(),
        destination_chain: DESTINATION_CHAIN.parse().unwrap(),
        destination_address: nonempty::String::try_from("A4f10f76B86E01B98daF66A3d02a65e14adb0767")
            .unwrap(),
        payload_hash,
        transfer_amount: amount,
        gas_fee_amount: XRPLPaymentAmount::Drops(1_000),
    }
}

fn call_contract_message(id: &str, payload_hash: [u8; 32]) -> XRPLCallContractMessage {
    XRPLCallContractMessage {
        tx_id: message_id(id),
        source_address: XRPL_USER.parse().unwrap(),
        destination_chain: DESTINATION_CHAIN.parse().unwrap(),
        destination_address: nonempty::String::try_from(
            "0xA4f10f76B86E01B98daF66A3d02a65e14adb0767",
        )
        .unwrap(),
        payload_hash,
        gas_fee_amount: XRPLPaymentAmount::Drops(1_000),
    }
}

fn add_gas_message(id: &str, amount: XRPLPaymentAmount) -> XRPLAddGasMessage {
    XRPLAddGasMessage {
        tx_id: message_id(id),
        msg_id: message_id("original"),
        amount,
        source_address: XRPL_USER.parse().unwrap(),
    }
}

fn route_incoming(
    deps: &mut AxelarDeps,
    message: XRPLMessage,
    payload: Option<nonempty::HexBinary>,
) -> Result<Response, ContractError> {
    execute_as(
        deps,
        SENDER,
        ExecuteMsg::RouteIncomingMessages(vec![WithPayload::new(message, payload)]),
    )
}

fn event<'a>(response: &'a Response, ty: &str) -> &'a Event {
    response
        .events
        .iter()
        .find(|event| event.ty == ty)
        .unwrap_or_else(|| panic!("no {ty} event in {:?}", response.events))
}

fn attribute<'a>(event: &'a Event, key: &str) -> &'a str {
    &event
        .attributes
        .iter()
        .find(|attribute| attribute.key == key)
        .unwrap_or_else(|| panic!("no {key} attribute in {:?}", event))
        .value
}

fn has_attribute(event: &Event, key: &str) -> bool {
    event
        .attributes
        .iter()
        .any(|attribute| attribute.key == key)
}

/// The messages the response forwards to the router.
fn routed_messages(deps: &AxelarDeps, response: &Response) -> Vec<Message> {
    let router = deps.api.addr_make(ROUTER);
    response
        .messages
        .iter()
        .flat_map(|sub_msg| match &sub_msg.msg {
            CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr, msg, ..
            }) if contract_addr == router.as_str() => match from_json(msg).unwrap() {
                router_api::msg::ExecuteMsg::RouteMessages(messages) => messages,
                other => panic!("unexpected router message {:?}", other),
            },
            other => panic!("unexpected message {:?}", other),
        })
        .collect()
}

/// The ITS hub message carried by the `contract_called` event.
fn routed_hub_message(response: &Response) -> HubMessage {
    let payload =
        HexBinary::from_hex(attribute(event(response, "contract_called"), "payload")).unwrap();
    hub_message_abi_decode(payload).unwrap()
}

/// Checks that the response routes exactly one message from the XRPL multisig to the ITS hub,
/// carrying the payload of the `contract_called` event.
fn assert_routed_to_its_hub(deps: &AxelarDeps, response: &Response) {
    let messages = routed_messages(deps, response);
    assert_eq!(messages.len(), 1, "{:?}", messages);
    let message = &messages[0];
    let payload =
        HexBinary::from_hex(attribute(event(response, "contract_called"), "payload")).unwrap();

    assert_eq!(message.source_address.to_string(), XRPL_MULTISIG);
    assert_eq!(
        message.destination_address.to_string(),
        deps.api.addr_make(ITS_HUB).to_string()
    );
    assert_eq!(
        message.destination_chain,
        ChainName::from_str("axelar").unwrap()
    );
    assert_eq!(
        message.cc_id.source_chain,
        ChainNameRaw::from_str("xrpl").unwrap()
    );
    assert_eq!(
        message.payload_hash,
        <[u8; 32]>::from(Keccak256::digest(payload.as_slice()))
    );
    assert_eq!(
        attribute(event(response, "routing_incoming"), "message_id"),
        message.cc_id.message_id.to_string()
    );
}

fn assert_permission_denied(result: Result<Response, ContractError>) {
    let err = result.expect_err("expected the permission check to fail");
    assert!(err_contains!(
        err.report,
        permission_control::Error,
        permission_control::Error::GeneralPermissionDenied { .. }
    ));
}

#[test]
fn xrp_token_id_is_the_linked_token_id_of_the_xrp_pseudo_issuer() {
    let deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);

    let xrp_token_id = xrp_token_id(&deps);

    let expected: TokenId = query_as(
        &deps,
        QueryMsg::LinkedTokenId(XRPLToken {
            issuer: "rrrrrrrrrrrrrrrrrrrrrhoLvTp".parse().unwrap(),
            currency: XRPLCurrency::XRP,
        }),
    )
    .unwrap();
    assert_eq!(xrp_token_id, expected);
    // XRP has no issuer, so it is not stored as an XRPL token
    assert!(query_as::<XRPLToken>(&deps, QueryMsg::XrplToken(xrp_token_id)).is_err());
}

#[test]
fn register_local_token_stores_token_and_emits_event() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token = usd_token();

    let response = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterLocalToken {
            xrpl_token: token.clone(),
        },
    )
    .unwrap();

    let linked_token_id: TokenId = query_as(&deps, QueryMsg::LinkedTokenId(token.clone())).unwrap();
    let event = event(&response, "local_token_registered");
    assert_eq!(attribute(event, "token_id"), linked_token_id.to_string());
    assert_eq!(attribute(event, "token"), token.to_string());

    assert_eq!(
        query_as::<TokenId>(&deps, QueryMsg::XrplTokenId(token.clone())).unwrap(),
        linked_token_id
    );
    assert_eq!(
        query_as::<XRPLToken>(&deps, QueryMsg::XrplToken(linked_token_id)).unwrap(),
        token
    );
}

#[test]
fn register_local_token_twice_is_a_no_op() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token = usd_token();
    let token_id = register_local_token(&mut deps, token.clone());

    let response = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterLocalToken {
            xrpl_token: token.clone(),
        },
    )
    .unwrap();

    assert!(response.events.is_empty());
    assert_eq!(
        query_as::<TokenId>(&deps, QueryMsg::XrplTokenId(token)).unwrap(),
        token_id
    );
}

#[test]
fn register_local_token_rejects_token_issued_by_the_multisig() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token = XRPLToken {
        issuer: xrpl_multisig(),
        currency: currency("USD"),
    };

    let err = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterLocalToken { xrpl_token: token },
    )
    .unwrap_err();

    assert!(err_contains!(err.report, Error, Error::TokenNotLocal(_)));
}

#[test]
fn register_local_token_rejects_token_id_taken_by_remote_token() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token = usd_token();
    let token_id: TokenId = query_as(&deps, QueryMsg::LinkedTokenId(token.clone())).unwrap();
    execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterRemoteToken {
            token_id,
            xrpl_currency: token.currency.clone(),
        },
    )
    .unwrap();

    let err = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterLocalToken { xrpl_token: token },
    )
    .unwrap_err();

    assert!(err_contains!(
        err.report,
        Error,
        Error::LocalTokenDeployedMismatch { .. }
    ));
}

#[test]
fn register_remote_token_stores_token_and_emits_event() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token_id = TokenId::new([1u8; 32]);

    let response = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterRemoteToken {
            token_id,
            xrpl_currency: currency("ETH"),
        },
    )
    .unwrap();

    let expected = XRPLToken {
        issuer: xrpl_multisig(),
        currency: currency("ETH"),
    };
    let event = event(&response, "remote_token_registered");
    assert_eq!(attribute(event, "token_id"), token_id.to_string());
    assert_eq!(attribute(event, "token"), expected.to_string());

    assert_eq!(
        query_as::<XRPLToken>(&deps, QueryMsg::XrplToken(token_id)).unwrap(),
        expected
    );
    assert_eq!(
        query_as::<TokenId>(&deps, QueryMsg::XrplTokenId(expected)).unwrap(),
        token_id
    );
}

#[test]
fn register_remote_token_twice_is_a_no_op() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let msg = ExecuteMsg::RegisterRemoteToken {
        token_id: TokenId::new([1u8; 32]),
        xrpl_currency: currency("ETH"),
    };
    execute_as(&mut deps, ADMIN, msg.clone()).unwrap();

    let response = execute_as(&mut deps, ADMIN, msg).unwrap();

    assert!(response.events.is_empty());
}

#[test]
fn register_remote_token_rejects_conflicting_registrations() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token_id = TokenId::new([1u8; 32]);
    execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterRemoteToken {
            token_id,
            xrpl_currency: currency("ETH"),
        },
    )
    .unwrap();

    // same currency for another token id
    let err = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterRemoteToken {
            token_id: TokenId::new([2u8; 32]),
            xrpl_currency: currency("ETH"),
        },
    )
    .unwrap_err();
    assert!(err_contains!(
        err.report,
        Error,
        Error::RemoteTokenDeployedIdMismatch { .. }
    ));

    // another currency for the same token id
    let err = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterRemoteToken {
            token_id,
            xrpl_currency: currency("BTC"),
        },
    )
    .unwrap_err();
    assert!(err_contains!(
        err.report,
        Error,
        Error::RemoteTokenDeployedCurrencyMismatch { .. }
    ));
}

#[test]
fn register_remote_token_rejects_token_id_of_local_token() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token = usd_token();
    let token_id = register_local_token(&mut deps, token.clone());

    let err = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterRemoteToken {
            token_id,
            xrpl_currency: token.currency,
        },
    )
    .unwrap_err();

    assert!(err_contains!(
        err.report,
        Error,
        Error::RemoteTokenDeployedIssuerMismatch { .. }
    ));
}

#[test]
fn token_instance_decimals_query_asks_the_its_hub() {
    let deps = setup(VerificationStatus::SucceededOnSourceChain, 7);

    let decimals: u8 = query_as(
        &deps,
        QueryMsg::TokenInstanceDecimals {
            chain_name: DESTINATION_CHAIN.parse().unwrap(),
            token_id: TokenId::new([1u8; 32]),
        },
    )
    .unwrap();

    assert_eq!(decimals, 7);
}

#[test]
fn register_token_metadata_routes_hub_message() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token = usd_token();

    let response = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterTokenMetadata {
            xrpl_token: XRPLTokenOrXrp::Issued(token.clone()),
        },
    )
    .unwrap();

    let token_address: nonempty::HexBinary =
        token.to_string().as_bytes().to_vec().try_into().unwrap();
    assert_eq!(
        routed_hub_message(&response),
        HubMessage::RegisterTokenMetadata(RegisterTokenMetadata {
            decimals: 15,
            token_address: token_address.clone(),
        })
    );
    let event = event(&response, "token_metadata_registered");
    assert_eq!(attribute(event, "decimals"), "15");
    assert_eq!(attribute(event, "token_address"), token_address.to_string());
    assert_routed_to_its_hub(&deps, &response);
}

#[test]
fn register_token_metadata_for_xrp_uses_six_decimals() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);

    let response = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::RegisterTokenMetadata {
            xrpl_token: XRPLTokenOrXrp::Xrp,
        },
    )
    .unwrap();

    assert_eq!(
        routed_hub_message(&response),
        HubMessage::RegisterTokenMetadata(RegisterTokenMetadata {
            decimals: 6,
            token_address: b"XRP".to_vec().try_into().unwrap(),
        })
    );
    assert_routed_to_its_hub(&deps, &response);
}

#[test]
fn link_token_routes_hub_message_for_xrp() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token_id = xrp_token_id(&deps);
    let link_token = LinkToken {
        token_manager_type: Uint256::from(2u8),
        destination_token_address: HexBinary::from_hex("1234").unwrap().try_into().unwrap(),
        params: Some(HexBinary::from_hex("abcd").unwrap().try_into().unwrap()),
    };

    let response = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::LinkToken {
            token_id,
            destination_chain: DESTINATION_CHAIN.parse().unwrap(),
            link_token: link_token.clone(),
        },
    )
    .unwrap();

    assert_eq!(
        routed_hub_message(&response),
        HubMessage::SendToHub {
            destination_chain: DESTINATION_CHAIN.parse().unwrap(),
            message: ItsMessage::LinkToken(ItsLinkToken {
                token_id,
                token_manager_type: link_token.token_manager_type,
                source_token_address: b"XRP".to_vec().try_into().unwrap(),
                destination_token_address: link_token.destination_token_address,
                params: link_token.params,
            }),
        }
    );
    let event = event(&response, "link_token_started");
    assert_eq!(attribute(event, "token_id"), token_id.to_string());
    assert_eq!(attribute(event, "destination_chain"), DESTINATION_CHAIN);
    assert_eq!(attribute(event, "token_manager_type"), "2");
    assert_eq!(
        attribute(event, "source_token_address"),
        HexBinary::from(b"XRP".as_slice()).to_hex()
    );
    assert_eq!(attribute(event, "destination_token_address"), "1234");
    assert_eq!(attribute(event, "params"), "abcd");
    assert_routed_to_its_hub(&deps, &response);
}

#[test]
fn link_token_routes_hub_message_for_registered_token() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token = usd_token();
    let token_id = register_local_token(&mut deps, token.clone());

    let response = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::LinkToken {
            token_id,
            destination_chain: DESTINATION_CHAIN.parse().unwrap(),
            link_token: LinkToken {
                token_manager_type: Uint256::zero(),
                destination_token_address: HexBinary::from_hex("1234").unwrap().try_into().unwrap(),
                params: None,
            },
        },
    )
    .unwrap();

    match routed_hub_message(&response) {
        HubMessage::SendToHub {
            message: ItsMessage::LinkToken(link_token),
            ..
        } => {
            assert_eq!(link_token.token_id, token_id);
            assert_eq!(
                link_token.source_token_address,
                token.to_string().as_bytes().to_vec().try_into().unwrap()
            );
            assert_eq!(link_token.params, None);
        }
        other => panic!("unexpected hub message {:?}", other),
    }
    assert!(!has_attribute(
        event(&response, "link_token_started"),
        "params"
    ));
    assert_routed_to_its_hub(&deps, &response);
}

#[test]
fn link_token_rejects_unknown_token_and_xrpl_as_destination() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let xrp_token_id = xrp_token_id(&deps);
    let link_token = LinkToken {
        token_manager_type: Uint256::zero(),
        destination_token_address: HexBinary::from_hex("1234").unwrap().try_into().unwrap(),
        params: None,
    };

    let err = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::LinkToken {
            token_id: TokenId::new([9u8; 32]),
            destination_chain: DESTINATION_CHAIN.parse().unwrap(),
            link_token: link_token.clone(),
        },
    )
    .unwrap_err();
    assert!(err_contains!(err.report, Error, Error::InvalidToken));

    let err = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::LinkToken {
            token_id: xrp_token_id,
            destination_chain: "xrpl".parse().unwrap(),
            link_token,
        },
    )
    .unwrap_err();
    assert!(err_contains!(
        err.report,
        Error,
        Error::InvalidDestinationChain(_)
    ));
}

#[test]
fn deploy_remote_token_for_issued_token_uses_xrpl_issued_token_decimals() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token = usd_token();
    let token_id = register_local_token(&mut deps, token.clone());
    let token_metadata = TokenMetadata {
        name: "US Dollar".to_string().try_into().unwrap(),
        symbol: "USD".to_string().try_into().unwrap(),
    };

    let response = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::DeployRemoteToken {
            xrpl_token: XRPLTokenOrXrp::Issued(token),
            destination_chain: DESTINATION_CHAIN.parse().unwrap(),
            token_metadata: token_metadata.clone(),
        },
    )
    .unwrap();

    assert_eq!(
        routed_hub_message(&response),
        HubMessage::SendToHub {
            destination_chain: DESTINATION_CHAIN.parse().unwrap(),
            message: ItsMessage::DeployInterchainToken(DeployInterchainToken {
                token_id,
                name: token_metadata.name,
                symbol: token_metadata.symbol,
                decimals: 15,
                minter: None,
            }),
        }
    );
    let event = event(&response, "interchain_token_deployment_started");
    assert_eq!(attribute(event, "token_id"), token_id.to_string());
    assert_eq!(attribute(event, "token_name"), "US Dollar");
    assert_eq!(attribute(event, "token_symbol"), "USD");
    assert_eq!(attribute(event, "token_decimals"), "15");
    assert_eq!(attribute(event, "destination_chain"), DESTINATION_CHAIN);
    assert!(!has_attribute(event, "minter"));
    assert_routed_to_its_hub(&deps, &response);
}

#[test]
fn deploy_remote_token_rejects_unregistered_token_and_xrpl_as_destination() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token_metadata = TokenMetadata {
        name: "US Dollar".to_string().try_into().unwrap(),
        symbol: "USD".to_string().try_into().unwrap(),
    };

    let err = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::DeployRemoteToken {
            xrpl_token: XRPLTokenOrXrp::Issued(usd_token()),
            destination_chain: DESTINATION_CHAIN.parse().unwrap(),
            token_metadata: token_metadata.clone(),
        },
    )
    .unwrap_err();
    assert!(err_contains!(err.report, Error, Error::InvalidToken));

    let err = execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::DeployRemoteToken {
            xrpl_token: XRPLTokenOrXrp::Xrp,
            destination_chain: "xrpl".parse().unwrap(),
            token_metadata,
        },
    )
    .unwrap_err();
    assert!(err_contains!(
        err.report,
        Error,
        Error::InvalidDestinationChain(_)
    ));
}

#[test]
fn elevated_messages_reject_unprivileged_senders() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let new_admin = deps.api.addr_make("new-admin").to_string();
    let token_metadata = TokenMetadata {
        name: "US Dollar".to_string().try_into().unwrap(),
        symbol: "USD".to_string().try_into().unwrap(),
    };

    let elevated_msgs = [
        ExecuteMsg::RegisterTokenMetadata {
            xrpl_token: XRPLTokenOrXrp::Xrp,
        },
        ExecuteMsg::RegisterLocalToken {
            xrpl_token: usd_token(),
        },
        ExecuteMsg::RegisterRemoteToken {
            token_id: TokenId::new([1u8; 32]),
            xrpl_currency: currency("ETH"),
        },
        ExecuteMsg::LinkToken {
            token_id: TokenId::new([1u8; 32]),
            destination_chain: DESTINATION_CHAIN.parse().unwrap(),
            link_token: LinkToken {
                token_manager_type: Uint256::zero(),
                destination_token_address: HexBinary::from_hex("1234").unwrap().try_into().unwrap(),
                params: None,
            },
        },
        ExecuteMsg::DeployRemoteToken {
            xrpl_token: XRPLTokenOrXrp::Xrp,
            destination_chain: DESTINATION_CHAIN.parse().unwrap(),
            token_metadata,
        },
        ExecuteMsg::UpdateAdmin {
            new_admin_address: new_admin,
        },
        ExecuteMsg::DisableExecution,
        ExecuteMsg::EnableExecution,
    ];

    for msg in elevated_msgs {
        assert_permission_denied(execute_as(&mut deps, SENDER, msg));
    }
}

#[test]
fn only_the_router_can_route_outgoing_messages() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let msgs = generate_outgoing_msgs("not router", 1);

    for sender in [SENDER, ADMIN, GOVERNANCE] {
        let err =
            execute_as(&mut deps, sender, ExecuteMsg::RouteMessages(msgs.clone())).unwrap_err();
        assert!(err_contains!(err.report, permission_control::Error, _));
    }
}

#[test]
fn disabling_execution_blocks_incoming_traffic_until_re_enabled() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let msgs = generate_incoming_msgs("killswitch", 2);

    let response = execute_as(&mut deps, ADMIN, ExecuteMsg::DisableExecution).unwrap();
    event(&response, "execution_disabled");
    assert!(!query_as::<bool>(&deps, QueryMsg::IsEnabled).unwrap());

    let err = execute_as(&mut deps, SENDER, ExecuteMsg::VerifyMessages(msgs.clone())).unwrap_err();
    assert!(err_contains!(err.report, Error, Error::ExecutionDisabled));
    let err = execute_as(
        &mut deps,
        SENDER,
        ExecuteMsg::RouteIncomingMessages(messages_with_payload(msgs.clone())),
    )
    .unwrap_err();
    assert!(err_contains!(err.report, Error, Error::ExecutionDisabled));
    // outgoing messages were already verified by their source chain, so they keep flowing
    execute_as(
        &mut deps,
        ROUTER,
        ExecuteMsg::RouteMessages(generate_outgoing_msgs("killswitch", 1)),
    )
    .unwrap();

    let response = execute_as(&mut deps, GOVERNANCE, ExecuteMsg::EnableExecution).unwrap();
    event(&response, "execution_enabled");
    assert!(query_as::<bool>(&deps, QueryMsg::IsEnabled).unwrap());
    execute_as(&mut deps, SENDER, ExecuteMsg::VerifyMessages(msgs)).unwrap();
}

#[test]
fn update_admin_transfers_the_admin_role() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let new_admin = "new-admin";
    let new_admin_address = deps.api.addr_make(new_admin).to_string();

    execute_as(
        &mut deps,
        ADMIN,
        ExecuteMsg::UpdateAdmin { new_admin_address },
    )
    .unwrap();

    assert_permission_denied(execute_as(&mut deps, ADMIN, ExecuteMsg::DisableExecution));
    execute_as(&mut deps, new_admin, ExecuteMsg::DisableExecution).unwrap();
}

#[test]
fn update_admin_rejects_invalid_address() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);

    let err = execute_as(
        &mut deps,
        GOVERNANCE,
        ExecuteMsg::UpdateAdmin {
            new_admin_address: "not an address".to_string(),
        },
    )
    .unwrap_err();

    assert!(err_contains!(err.report, Error, Error::FailedToUpdateAdmin));
}

#[test]
fn route_incoming_call_contract_message() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let payload = payload();
    let message = call_contract_message("call", keccak(&payload));

    let response = route_incoming(
        &mut deps,
        XRPLMessage::CallContractMessage(message.clone()),
        Some(payload.clone()),
    )
    .unwrap();

    assert_eq!(
        routed_messages(&deps, &response),
        vec![Message {
            cc_id: message.cc_id("xrpl".parse().unwrap()),
            source_address: XRPL_USER.parse().unwrap(),
            destination_address: message.destination_address.as_str().parse().unwrap(),
            destination_chain: DESTINATION_CHAIN.parse().unwrap(),
            payload_hash: message.payload_hash,
        }]
    );
    assert_eq!(
        attribute(event(&response, "contract_called"), "payload"),
        payload.to_string()
    );
    event(&response, "routing_incoming");
    assert!(!response
        .events
        .iter()
        .any(|event| event.ty == "interchain_transfer"));
}

#[test]
fn route_incoming_call_contract_requires_matching_payload() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let payload = payload();
    let message = call_contract_message("call", keccak(&payload));
    let wrong_payload = nonempty::HexBinary::try_from(HexBinary::from_hex("ff").unwrap()).unwrap();

    let err = route_incoming(
        &mut deps,
        XRPLMessage::CallContractMessage(message.clone()),
        None,
    )
    .unwrap_err();
    assert!(err_contains!(err.report, Error, Error::PayloadHashEmpty));

    let err = route_incoming(
        &mut deps,
        XRPLMessage::CallContractMessage(message.clone()),
        Some(wrong_payload.clone()),
    )
    .unwrap_err();
    assert!(err_contains!(
        err.report,
        Error,
        Error::PayloadHashMismatch { expected, actual }
            if expected.as_slice() == message.payload_hash
                && actual.as_slice() == keccak(&wrong_payload)
    ));
}

#[test]
fn route_incoming_rejects_messages_that_are_not_user_calls() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let unsupported = [
        XRPLMessage::AddGasMessage(add_gas_message("gas", XRPLPaymentAmount::Drops(1))),
        XRPLMessage::AddReservesMessage(XRPLAddReservesMessage {
            tx_id: message_id("reserves"),
            amount: 1,
        }),
        XRPLMessage::ProverMessage(XRPLProverMessage {
            tx_id: message_id("prover"),
            unsigned_tx_hash: message_id("unsigned"),
        }),
    ];

    for message in unsupported {
        let err = route_incoming(&mut deps, message, None).unwrap_err();
        assert!(err_contains!(
            err.report,
            Error,
            Error::UnsupportedIncomingMessage(_)
        ));
    }
}

#[test]
fn interchain_transfer_payload_must_match_its_hash() {
    let deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let payload = payload();
    let wrong_payload = nonempty::HexBinary::try_from(HexBinary::from_hex("ff").unwrap()).unwrap();
    let drops = XRPLPaymentAmount::Drops(1_000_000);

    // hash without payload
    let message = interchain_transfer_message("transfer", drops.clone(), Some(keccak(&payload)));
    let err = query_as::<InterchainTransfer>(
        &deps,
        QueryMsg::InterchainTransfer {
            message: message.clone(),
            payload: None,
        },
    )
    .unwrap_err();
    assert!(err_contains!(
        err.report,
        Error,
        Error::PayloadHashGivenWithoutPayload(_)
    ));

    // payload that does not hash to the given hash
    let err = query_as::<InterchainTransfer>(
        &deps,
        QueryMsg::InterchainTransfer {
            message: message.clone(),
            payload: Some(wrong_payload.clone()),
        },
    )
    .unwrap_err();
    assert!(err_contains!(
        err.report,
        Error,
        Error::PayloadHashMismatch { expected, actual }
            if expected.as_slice() == keccak(&payload)
                && actual.as_slice() == keccak(&wrong_payload)
    ));

    // payload without hash
    let err = query_as::<InterchainTransfer>(
        &deps,
        QueryMsg::InterchainTransfer {
            message: interchain_transfer_message("transfer", drops, None),
            payload: Some(payload.clone()),
        },
    )
    .unwrap_err();
    assert!(err_contains!(err.report, Error, Error::PayloadHashEmpty));

    // matching payload travels to the hub as the transfer's data
    let transfer: InterchainTransfer = query_as(
        &deps,
        QueryMsg::InterchainTransfer {
            message,
            payload: Some(payload.clone()),
        },
    )
    .unwrap();
    let hub_payload: HexBinary = transfer.message_with_payload.unwrap().payload.into();
    match hub_message_abi_decode(hub_payload).unwrap() {
        HubMessage::SendToHub {
            message: ItsMessage::InterchainTransfer(transfer),
            ..
        } => {
            assert_eq!(transfer.data, Some(payload));
            assert_eq!(
                transfer.amount,
                nonempty::Uint256::try_from(Uint256::from(1_000_000u128)).unwrap()
            );
        }
        other => panic!("unexpected hub message {:?}", other),
    }
}

#[test]
fn route_incoming_interchain_transfer_with_payload_emits_data_hash() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let payload = payload();
    let message = interchain_transfer_message(
        "transfer",
        XRPLPaymentAmount::Drops(1_000_000),
        Some(keccak(&payload)),
    );

    let response = route_incoming(
        &mut deps,
        XRPLMessage::InterchainTransferMessage(message.clone()),
        Some(payload.clone()),
    )
    .unwrap();

    let event = event(&response, "interchain_transfer");
    assert_eq!(
        attribute(event, "token_id"),
        xrp_token_id(&deps).to_string()
    );
    assert_eq!(attribute(event, "source_address"), XRPL_USER);
    assert_eq!(attribute(event, "destination_chain"), DESTINATION_CHAIN);
    assert_eq!(
        attribute(event, "destination_address"),
        message.destination_address.to_string().to_lowercase()
    );
    assert_eq!(attribute(event, "amount"), "1000000");
    assert_eq!(
        attribute(event, "data_hash"),
        HexBinary::from(keccak(&payload)).to_hex()
    );
    assert_eq!(routed_messages(&deps, &response).len(), 1);
}

#[test]
fn route_incoming_issued_token_transfer_scales_amount_with_xrpl_hub_decimals() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token = usd_token();
    let token_id = register_local_token(&mut deps, token.clone());
    let message = interchain_transfer_message("usd", one_and_a_half(token), None);

    let response = route_incoming(
        &mut deps,
        XRPLMessage::InterchainTransferMessage(message),
        None,
    )
    .unwrap();

    assert_eq!(routed_messages(&deps, &response).len(), 1);
    match routed_hub_message(&response) {
        HubMessage::SendToHub {
            destination_chain,
            message: ItsMessage::InterchainTransfer(transfer),
        } => {
            assert_eq!(destination_chain, DESTINATION_CHAIN);
            assert_eq!(transfer.token_id, token_id);
            // 1.5 USD at the hub's 15 decimals
            assert_eq!(
                transfer.amount,
                nonempty::Uint256::try_from(Uint256::from(1_500_000_000_000_000u128)).unwrap()
            );
            assert_eq!(transfer.data, None);
        }
        other => panic!("unexpected hub message {:?}", other),
    }
    assert!(!has_attribute(
        event(&response, "interchain_transfer"),
        "data_hash"
    ));
}

#[test]
fn route_incoming_transfer_below_hub_precision_routes_nothing() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let token = usd_token();
    register_local_token(&mut deps, token.clone());
    // 1e-20 USD has no representation at the hub's 15 decimals
    let dust = XRPLPaymentAmount::Issued(token, XRPLTokenAmount::new(1_000_000_000_000_000, -35));
    let message = interchain_transfer_message("dust", dust, None);

    let response = route_incoming(
        &mut deps,
        XRPLMessage::InterchainTransferMessage(message),
        None,
    )
    .unwrap();

    assert!(response.messages.is_empty());
    assert!(response.events.is_empty());
}

#[test]
fn route_incoming_transfer_of_unregistered_token_fails() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let message = interchain_transfer_message("unknown", one_and_a_half(usd_token()), None);

    let err = route_incoming(
        &mut deps,
        XRPLMessage::InterchainTransferMessage(message),
        None,
    )
    .unwrap_err();

    assert!(err_contains!(err.report, Error, Error::State));
}

#[test]
fn route_incoming_transfer_rejects_hub_decimals_above_maximum() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, 51);
    let token = usd_token();
    register_local_token(&mut deps, token.clone());
    let message = interchain_transfer_message("usd", one_and_a_half(token), None);

    let err = route_incoming(
        &mut deps,
        XRPLMessage::InterchainTransferMessage(message),
        None,
    )
    .unwrap_err();

    assert!(err_contains!(err.report, Error, Error::InvalidDecimals(51)));
}

#[test]
fn route_incoming_accepts_the_same_message_twice() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let message = XRPLMessage::InterchainTransferMessage(interchain_transfer_message(
        "twice",
        XRPLPaymentAmount::Drops(1_000_000),
        None,
    ));

    let first = route_incoming(&mut deps, message.clone(), None).unwrap();
    let second = route_incoming(&mut deps, message, None).unwrap();

    assert_eq!(first, second);
}

#[test]
fn call_contract_query_translates_message() {
    let deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let payload = payload();
    let message = call_contract_message("call", keccak(&payload));

    let call_contract: CallContract = query_as(
        &deps,
        QueryMsg::CallContract {
            message: message.clone(),
            payload: payload.clone(),
        },
    )
    .unwrap();

    assert_eq!(call_contract.gas_token_id, xrp_token_id(&deps));
    assert_eq!(call_contract.message_with_payload.payload, payload);
    assert_eq!(
        call_contract.message_with_payload.message.cc_id,
        message.cc_id("xrpl".parse().unwrap())
    );
    assert_eq!(
        call_contract.message_with_payload.message.payload_hash,
        message.payload_hash
    );
}

#[test]
fn confirm_add_gas_messages_resolves_tokens_of_verified_messages_only() {
    let unregistered = one_and_a_half(usd_token());

    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    execute_as(
        &mut deps,
        SENDER,
        ExecuteMsg::ConfirmAddGasMessages(vec![add_gas_message(
            "xrp",
            XRPLPaymentAmount::Drops(10),
        )]),
    )
    .unwrap();
    let err = execute_as(
        &mut deps,
        SENDER,
        ExecuteMsg::ConfirmAddGasMessages(vec![add_gas_message("iou", unregistered.clone())]),
    )
    .unwrap_err();
    assert!(err_contains!(err.report, Error, Error::State));
    let err = execute_as(
        &mut deps,
        SENDER,
        ExecuteMsg::ConfirmAddGasMessages(vec![
            add_gas_message("dup", XRPLPaymentAmount::Drops(10)),
            add_gas_message("dup", XRPLPaymentAmount::Drops(20)),
        ]),
    )
    .unwrap_err();
    assert!(err_contains!(err.report, Error, Error::DuplicateMessageIds));

    // unverified messages are skipped before their token is looked up
    let mut deps = setup(VerificationStatus::NotFoundOnSourceChain, HUB_DECIMALS);
    execute_as(
        &mut deps,
        SENDER,
        ExecuteMsg::ConfirmAddGasMessages(vec![add_gas_message("iou", unregistered)]),
    )
    .unwrap();
}

#[test]
fn route_outgoing_rejects_messages_not_coming_from_the_its_hub() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let msgs = generate_outgoing_msgs("outgoing", 1);

    let mut from_another_sender = msgs.clone();
    from_another_sender[0].source_address =
        deps.api.addr_make("not-its-hub").as_str().parse().unwrap();
    let err = execute_as(
        &mut deps,
        ROUTER,
        ExecuteMsg::RouteMessages(from_another_sender),
    )
    .unwrap_err();
    assert!(err_contains!(err.report, Error, Error::OnlyFromItsHub(_)));

    let mut from_another_chain = msgs;
    from_another_chain[0].cc_id = CrossChainId::new(DESTINATION_CHAIN, "0x1234").unwrap();
    let err = execute_as(
        &mut deps,
        ROUTER,
        ExecuteMsg::RouteMessages(from_another_chain),
    )
    .unwrap_err();
    assert!(err_contains!(
        err.report,
        Error,
        Error::OnlyFromItsHubChain(_)
    ));
}

#[test]
fn route_outgoing_accepts_the_same_messages_twice() {
    let mut deps = setup(VerificationStatus::SucceededOnSourceChain, HUB_DECIMALS);
    let msgs = generate_outgoing_msgs("twice", 3);

    let first = execute_as(&mut deps, ROUTER, ExecuteMsg::RouteMessages(msgs.clone())).unwrap();
    let second = execute_as(&mut deps, ROUTER, ExecuteMsg::RouteMessages(msgs.clone())).unwrap();

    assert_eq!(first, second);
    let stored: Vec<Message> = query_as(
        &deps,
        QueryMsg::OutgoingMessages(msgs.iter().map(|msg| msg.cc_id.clone()).collect()),
    )
    .unwrap();
    assert_eq!(stored, msgs);
}

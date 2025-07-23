use assert_ok::assert_ok;
use axelar_core_std::nexus::test_utils::reply_with_is_chain_registered;
use axelar_core_std::query::AxelarQueryMsg;
use axelar_wasm_std::response::inspect_response_msg;
use axelarnet_gateway::msg::QueryMsg;
use axelarnet_gateway::{contract, ExecutableMessage};
use cosmwasm_std::testing::{
    message_info, mock_dependencies, mock_env, MockApi, MockQuerier,
    MockQuerierCustomHandlerResult, MockStorage,
};
use cosmwasm_std::{from_json, ContractResult, Deps, OwnedDeps, SystemResult};
use rand::RngCore;
use router_api::msg::ExecuteMsg as RouterExecuteMsg;
use router_api::{ChainName, CrossChainId, Message};
use serde_json::json;
use sha3::{Digest, Keccak256};

use crate::utils::{mock_axelar_dependencies, params, OwnedDepsExt};

mod utils;

#[test]
fn query_routable_messages_gets_expected_messages() {
    let mut deps = mock_axelar_dependencies();
    deps.querier = deps
        .querier
        .with_custom_handler(reply_rand_tx_hash_and_nonce);

    utils::instantiate_contract(deps.as_default_mut()).unwrap();
    let mut expected = populate_routable_messages(&mut deps);

    expected.remove(3);
    let cc_ids = expected.iter().map(|msg| &msg.cc_id).cloned().collect();

    assert_eq!(
        assert_ok!(query_routable_messages(deps.as_default_deps(), cc_ids)),
        expected,
    );
}

#[test]
fn query_executable_messages_gets_expected_messages() {
    let mut deps = mock_axelar_dependencies();
    deps.querier = deps
        .querier
        .with_custom_handler(reply_with_is_chain_registered(false));

    utils::instantiate_contract(deps.as_default_mut()).unwrap();
    let mut cc_ids = populate_executable_messages(&mut deps);
    cc_ids.remove(3);

    let executable_message = assert_ok!(query_executable_messages(deps.as_default_deps(), cc_ids));
    goldie::assert_json!(executable_message);
}

#[test]
fn query_chain_name_gets_expected_chain() {
    let mut deps = mock_dependencies();

    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_eq!(
        assert_ok!(query_chain_name(deps.as_ref())).as_ref(),
        params::AXELARNET,
    );
}

fn query_routable_messages(deps: Deps, cc_ids: Vec<CrossChainId>) -> Result<Vec<Message>, ()> {
    from_json(
        contract::query(deps, mock_env(), QueryMsg::RoutableMessages { cc_ids }).map_err(|_| ())?,
    )
    .map_err(|_| ())
}

fn query_executable_messages(
    deps: Deps,
    cc_ids: Vec<CrossChainId>,
) -> Result<Vec<ExecutableMessage>, ()> {
    from_json(
        contract::query(deps, mock_env(), QueryMsg::ExecutableMessages { cc_ids })
            .map_err(|_| ())?,
    )
    .map_err(|_| ())
}

fn query_chain_name(deps: Deps) -> Result<ChainName, ()> {
    from_json(contract::query(deps, mock_env(), QueryMsg::ChainName).map_err(|_| ())?)
        .map_err(|_| ())
}

fn populate_routable_messages(
    deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier<AxelarQueryMsg>, AxelarQueryMsg>,
) -> Vec<Message> {
    let api = deps.api;

    (0..10)
        .map(|i| {
            let response = utils::call_contract(
                deps.as_default_mut(),
                message_info(&api.addr_make("sender"), &[]),
                format!("destination-chain-{}", i).parse().unwrap(),
                format!("destination-address-{}", i).parse().unwrap(),
                vec![i].into(),
            )
            .unwrap();

            let RouterExecuteMsg::RouteMessages(mut msgs) = inspect_response_msg(response).unwrap()
            else {
                panic!("pattern must match")
            };

            msgs.pop().unwrap()
        })
        .collect()
}

fn populate_executable_messages(
    deps: &mut OwnedDeps<MockStorage, MockApi, MockQuerier<AxelarQueryMsg>, AxelarQueryMsg>,
) -> Vec<CrossChainId> {
    let msgs: Vec<_> = (0..10)
        .map(|i| Message {
            cc_id: CrossChainId::new("source-chain", format!("hash-index-{}", i)).unwrap(),
            source_address: "source-address".parse().unwrap(),
            destination_chain: params::AXELARNET.parse().unwrap(),
            destination_address: deps
                .api
                .addr_make("destination-address")
                .to_string()
                .parse()
                .unwrap(),
            payload_hash: Keccak256::digest(vec![i]).into(),
        })
        .collect();

    utils::route_from_router(deps.as_default_mut(), msgs.clone()).unwrap();

    utils::execute_payload(deps.as_default_mut(), msgs[0].cc_id.clone(), vec![0].into()).unwrap();
    utils::execute_payload(deps.as_default_mut(), msgs[5].cc_id.clone(), vec![5].into()).unwrap();
    utils::execute_payload(deps.as_default_mut(), msgs[7].cc_id.clone(), vec![7].into()).unwrap();

    msgs.into_iter().map(|msg| msg.cc_id).collect()
}

pub fn reply_rand_tx_hash_and_nonce(query: &AxelarQueryMsg) -> MockQuerierCustomHandlerResult {
    let result = match query {
        AxelarQueryMsg::Nexus(nexus_query) => match nexus_query {
            axelar_core_std::nexus::query::QueryMsg::TxHashAndNonce {} => {
                let mut tx_hash = [0u8; 32];
                rand::rng().fill_bytes(&mut tx_hash);
                let nonce: u32 = rand::random();

                json!({
                    "tx_hash": tx_hash,
                    "nonce": nonce,
                })
            }
            axelar_core_std::nexus::query::QueryMsg::IsChainRegistered { chain: _ } => json!({
                "is_registered": false
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

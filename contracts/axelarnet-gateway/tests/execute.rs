use axelar_wasm_std::error::ContractError;
use axelarnet_gateway::contract;
use axelarnet_gateway::msg::ExecuteMsg;
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use cosmwasm_std::{DepsMut, HexBinary, Response};
use router_api::{CrossChainId, Message};
use sha3::Digest;

use crate::utils::instantiate::instantiate_contract;
use crate::utils::params;

mod utils;

#[test]
fn message_not_approved() {
    let mut deps = mock_dependencies();

    instantiate_contract(deps.as_mut()).unwrap();

    assert!(contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info("sender", &[]),
        ExecuteMsg::Execute {
            cc_id: CrossChainId::new("source-chain", "hash-index").unwrap(),
            payload: vec![1, 2, 3].into(),
        },
    )
    .is_ok());
}

#[test]
fn message_already_executed() {
    let mut deps = mock_dependencies();

    let cc_id = CrossChainId::new("chain", "hash-index").unwrap();
    let payload: HexBinary = vec![1, 2, 3].into();

    let msgs = vec![Message {
        cc_id: cc_id.clone(),
        source_address: "source-address".parse().unwrap(),
        destination_chain: "axelarnet".parse().unwrap(),
        destination_address: "destination-address".parse().unwrap(),
        payload_hash: sha3::Keccak256::digest(&payload).into(),
    }];

    instantiate_contract(deps.as_mut()).unwrap();
    route_from_router(deps.as_mut(), msgs).unwrap();
    execute_payload(deps.as_mut(), cc_id.clone(), payload.clone()).unwrap();

    assert!(execute_payload(deps.as_mut(), cc_id, payload).is_err());
}

fn execute_payload(
    deps: DepsMut,
    cc_id: CrossChainId,
    payload: HexBinary,
) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info("sender", &[]),
        ExecuteMsg::Execute { cc_id, payload }.clone(),
    )
}

fn route_from_router(deps: DepsMut, msgs: Vec<Message>) -> Result<Response, ContractError> {
    contract::execute(
        deps,
        mock_env(),
        mock_info(params::ROUTER, &[]),
        ExecuteMsg::RouteMessages(msgs),
    )
}

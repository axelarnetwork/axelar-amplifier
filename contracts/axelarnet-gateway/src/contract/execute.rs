use std::str::FromStr;

use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use axelar_wasm_std::{FnExt, IntoContractError};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, HexBinary, Response, Storage, Uint256};
use error_stack::{bail, ensure, report, Result, ResultExt};
use itertools::Itertools;
use router_api::client::Router;
use router_api::{Address, ChainName, CrossChainId, Message};
use sha3::{Digest, Keccak256};

use crate::clients::CrossChainExecutor;
use crate::events::AxelarnetGatewayEvent;
use crate::state;
use crate::state::Config;

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("failed to save executable message")]
    SaveExecutableMessage,
    #[error("failed to access executable message")]
    ExecutableMessageAccess,
    #[error("message with ID {0} is different")]
    MessageMismatch(CrossChainId),
    #[error("failed to mark message with ID {0} as executed")]
    MarkExecuted(CrossChainId),
    #[error("expected destination chain {expected}, got {actual}")]
    InvalidDestination {
        expected: ChainName,
        actual: ChainName,
    },
    #[error("failed to generate cross chain id")]
    CrossChainIdGeneration,
    #[error("unable to load the contract config")]
    ConfigAccess,
    #[error("unable to save the message before routing")]
    SaveRoutableMessage,
    #[error("invalid cross-chain id")]
    InvalidCrossChainId,
    #[error("failed to create executor")]
    CreateExecutor,
    #[error("not allowed to execute payload")]
    PayloadNotApproved,
    #[error("unable to generate event index")]
    EventIndex,
    #[error("invalid source address {0}")]
    InvalidSourceAddress(Addr),
}

#[cw_serde]
pub struct CallContractData {
    pub destination_chain: ChainName,
    pub destination_address: Address,
    pub payload: HexBinary,
}

impl CallContractData {
    pub fn into_message(self, id: CrossChainId, source_address: Address) -> Message {
        Message {
            cc_id: id,
            source_address,
            destination_chain: self.destination_chain,
            destination_address: self.destination_address,
            payload_hash: Keccak256::digest(self.payload.as_slice()).into(),
        }
    }
}

pub fn call_contract(
    storage: &mut dyn Storage,
    block_height: u64,
    sender: Addr,
    call_contract: CallContractData,
) -> Result<Response, Error> {
    let payload = call_contract.payload.clone();

    let Config { router, chain_name } =
        state::load_config(storage).change_context(Error::ConfigAccess)?;

    let id = generate_cross_chain_id(storage, block_height, chain_name)
        .change_context(Error::CrossChainIdGeneration)?;
    let source_address = Address::from_str(sender.as_str())
        .change_context(Error::InvalidSourceAddress(sender.clone()))?;
    let msg = call_contract.into_message(id, source_address);

    state::save_unique_routable_msg(storage, &msg.cc_id, &msg)
        .inspect_err(|err| panic_if_already_exists(err, &msg.cc_id))
        .change_context(Error::SaveRoutableMessage)?;

    Ok(
        route_to_router(storage, &Router { address: router }, vec![msg.clone()])?
            .add_event(AxelarnetGatewayEvent::ContractCalled { msg, payload }.into()),
    )
}

pub fn route_messages(
    storage: &mut dyn Storage,
    sender: Addr,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    let Config { chain_name, router } =
        state::load_config(storage).change_context(Error::ConfigAccess)?;
    let router = Router { address: router };

    if sender == router.address {
        Ok(prepare_msgs_for_execution(storage, chain_name, msgs)?)
    } else {
        // Messages initiated via call contract can be routed again
        Ok(route_to_router(storage, &router, msgs)?)
    }
}

pub fn execute(deps: DepsMut, cc_id: CrossChainId, payload: HexBinary) -> Result<Response, Error> {
    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();
    let msg = state::update_as_executed(deps.storage, &cc_id, |msg| {
        (payload_hash == msg.payload_hash)
            .then_some(msg)
            .ok_or(state::Error::PayloadHashMismatch)
    })
    .change_context(Error::MarkExecuted(cc_id.clone()))?;

    let executor = CrossChainExecutor::new(deps.as_ref(), &msg.destination_address)
        .change_context(Error::CreateExecutor)?;

    Response::new()
        .add_message(executor.prepare_execute_msg(cc_id, msg.source_address.clone(), payload))
        .add_event(AxelarnetGatewayEvent::MessageExecuted { msg }.into())
        .then(Ok)
}

fn generate_cross_chain_id(
    storage: &mut dyn Storage,
    block_height: u64,
    chain_name: ChainName,
) -> Result<CrossChainId, Error> {
    // TODO: Retrieve the actual tx hash from core, since cosmwasm doesn't provide it.
    // Use the block height as the placeholder in the meantime.
    let message_id = HexTxHashAndEventIndex {
        tx_hash: Uint256::from(block_height).to_be_bytes(),
        event_index: state::ROUTABLE_MESSAGES_INDEX
            .incr(storage)
            .change_context(Error::EventIndex)?,
    };

    CrossChainId::new(chain_name, message_id).change_context(Error::InvalidCrossChainId)
}

fn panic_if_already_exists(err: &state::Error, cc_id: &CrossChainId) {
    if matches!(err, state::Error::MessageAlreadyExists(..)) {
        panic!(
            "violated invariant: message with ID {0} already exists",
            cc_id
        )
    }
}

// Because the messages came from the router, we can assume they are already verified
fn prepare_msgs_for_execution(
    store: &mut dyn Storage,
    chain_name: ChainName,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    for msg in msgs.iter() {
        ensure!(
            chain_name == msg.destination_chain,
            Error::InvalidDestination {
                expected: chain_name,
                actual: msg.destination_chain.clone()
            }
        );

        state::save_executable_msg(store, &msg.cc_id, msg.clone())
            .change_context(Error::SaveExecutableMessage)?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into()),
    ))
}

/// Route messages to the router, ignore unknown messages.
fn route_to_router(
    store: &mut dyn Storage,
    router: &Router,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    let msgs: Vec<_> = msgs
        .into_iter()
        .unique()
        .filter_map(|msg| verify_message(store, msg).transpose())
        .try_collect()?;

    Ok(Response::new()
        .add_messages(router.route(msgs.clone()))
        .add_events(
            msgs.into_iter()
                .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into()),
        ))
}

/// Verify that the message is stored and matches the one we're trying to route. Returns Ok(None) if
/// the message is not stored.
fn verify_message(store: &mut dyn Storage, msg: Message) -> Result<Option<Message>, Error> {
    let stored_msg = state::may_load_routable_msg(store, &msg.cc_id)
        .change_context(Error::ExecutableMessageAccess)?;

    match stored_msg {
        Some(stored_msg) if stored_msg != msg => {
            bail!(Error::MessageMismatch(msg.cc_id.clone()))
        }
        Some(stored_msg) => Ok(Some(stored_msg)),
        None => Ok(None),
    }
}

// #[cfg(test)]
// mod tests {
//     use axelar_wasm_std::err_contains;
//     use cosmwasm_std::testing::{
//         mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
//     };
//     use cosmwasm_std::{Addr, CosmosMsg, Empty, Env, MessageInfo, OwnedDeps};
//     use router_api::{ChainName, CrossChainId, Message};
//
//     use super::*;
//     use crate::contract::{execute, instantiate};
//     use crate::msg::{CallContractData, ExecuteMsg, InstantiateMsg};
//     use crate::state::{self};
//
//     const CHAIN: &str = "chain";
//     const SOURCE_CHAIN: &str = "source-chain";
//     const ROUTER: &str = "router";
//     const PAYLOAD: [u8; 3] = [1, 2, 3];
//     const SENDER: &str = "sender";
//
//     fn setup() -> (
//         OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
//         Env,
//         MessageInfo,
//     ) {
//         let mut deps = mock_dependencies();
//         let env = mock_env();
//         let info = mock_info(SENDER, &[]);
//
//         let chain_name: ChainName = CHAIN.parse().unwrap();
//         let router = Addr::unchecked(ROUTER);
//
//         let msg = InstantiateMsg {
//             chain_name: chain_name.clone(),
//             router_address: router.to_string(),
//         };
//
//         let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
//
//         (deps, env, info)
//     }
//
//     fn dummy_message() -> Message {
//         Message {
//             cc_id: CrossChainId::new(SOURCE_CHAIN, "message-id").unwrap(),
//             source_address: "source-address".parse().unwrap(),
//             destination_chain: CHAIN.parse().unwrap(),
//             destination_address: "destination-address".parse().unwrap(),
//             payload_hash: Keccak256::digest(PAYLOAD).into(),
//         }
//     }
//
//     #[test]
//     fn call_contract_and_send_message() {
//         let (mut deps, env, info) = setup();
//
//         let expected_message_id = HexTxHashAndEventIndex {
//             tx_hash: Uint256::from(env.block.height).to_be_bytes(),
//             event_index: 1,
//         };
//         let expected_cc_id = CrossChainId::new(CHAIN, expected_message_id).unwrap();
//         let message = Message {
//             cc_id: expected_cc_id.clone(),
//             source_address: info.sender.clone().into_string().parse().unwrap(),
//             destination_chain: "destination-chain".parse().unwrap(),
//             destination_address: "destination-address".parse().unwrap(),
//             payload_hash: Keccak256::digest(PAYLOAD).into(),
//         };
//
//         let msg = ExecuteMsg::CallContract(CallContractData {
//             destination_chain: message.destination_chain.clone(),
//             destination_address: message.destination_address.clone(),
//             payload: PAYLOAD.into(),
//         });
//
//         let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
//         let sent_message =
//             state::may_load_contract_call_msg(deps.as_mut().storage, &expected_cc_id)
//                 .unwrap()
//                 .unwrap();
//         assert_eq!(sent_message, message);
//
//         let router: Router = Router {
//             address: Addr::unchecked(ROUTER),
//         };
//         assert_eq!(res.messages.len(), 1);
//         assert_eq!(
//             res.messages[0].msg,
//             CosmosMsg::Wasm(router.route(vec![message.clone()]).unwrap())
//         );
//
//         // Re-route the message again
//         let msg = ExecuteMsg::RouteMessages(vec![message.clone()]);
//         let res = execute(deps.as_mut(), env, info, msg).unwrap();
//         assert_eq!(res.messages.len(), 1);
//         assert_eq!(
//             res.messages[0].msg,
//             CosmosMsg::Wasm(router.route(vec![message]).unwrap())
//         );
//     }
//
//     #[test]
//     fn route_messages_from_router() {
//         let (mut deps, env, _) = setup();
//
//         let message = dummy_message();
//         let msg = ExecuteMsg::RouteMessages(vec![message.clone()]);
//
//         // Execute RouteMessages as if it's coming from the router
//         let info = mock_info(ROUTER, &[]);
//         execute(deps.as_mut(), env, info, msg).unwrap();
//
//         // Check that the message was saved as received
//         let received_message =
//             state::may_load_executable_msg(deps.as_mut().storage, &message.cc_id)
//                 .unwrap()
//                 .unwrap();
//         assert_eq!(received_message.msg, message);
//         assert!(matches!(received_message.status, MessageStatus::Approved));
//     }
//
//     #[test]
//     fn execute_message() {
//         let (mut deps, env, info) = setup();
//
//         let message = dummy_message();
//         let cc_id = message.cc_id.clone();
//
//         // Save the message as received
//         state::save_executable_msg(deps.as_mut().storage, cc_id.clone(), message).unwrap();
//
//         let msg = ExecuteMsg::Execute {
//             cc_id: cc_id.clone(),
//             payload: PAYLOAD.into(),
//         };
//
//         let res = execute(deps.as_mut(), env, info, msg).unwrap();
//
//         // Check that a message was sent to the destination contract
//         assert_eq!(res.messages.len(), 1);
//
//         // Check that the message status was updated to Executed
//         let executed_message = state::may_load_executable_msg(deps.as_mut().storage, &cc_id)
//             .unwrap()
//             .unwrap();
//         assert!(matches!(executed_message.status, MessageStatus::Executed));
//     }
//
//     #[test]
//     fn execute_not_found() {
//         let (mut deps, env, info) = setup();
//
//         let cc_id = CrossChainId::new(SOURCE_CHAIN, "message-id").unwrap();
//         let msg = ExecuteMsg::Execute {
//             cc_id: cc_id.clone(),
//             payload: PAYLOAD.into(),
//         };
//
//         let err = execute(deps.as_mut(), env, info, msg).unwrap_err();
//         assert!(err_contains!(
//             err.report,
//             state::Error,
//             state::Error::MessageNotApproved(..)
//         ));
//         assert!(err_contains!(err.report, Error, Error::MarkExecuted(..)));
//     }
//
//     #[test]
//     fn execute_already_executed() {
//         let (mut deps, env, info) = setup();
//
//         let message = dummy_message();
//         let cc_id = message.cc_id.clone();
//
//         // Save the message as already executed
//         state::save_executable_msg(deps.as_mut().storage, cc_id.clone(), message).unwrap();
//         state::mark_msg_as_executed(deps.as_mut().storage, cc_id.clone()).unwrap();
//
//         let msg = ExecuteMsg::Execute {
//             cc_id,
//             payload: PAYLOAD.into(),
//         };
//
//         let err = execute(deps.as_mut(), env, info, msg).unwrap_err();
//         assert!(err_contains!(
//             err.report,
//             state::Error,
//             state::Error::MessageAlreadyExecuted(..)
//         ));
//         assert!(err_contains!(err.report, Error, Error::MarkExecuted(..)));
//     }
//
//     #[test]
//     fn execute_payload_mismatch() {
//         let (mut deps, env, info) = setup();
//
//         let message = dummy_message();
//         let cc_id = message.cc_id.clone();
//
//         state::save_executable_msg(deps.as_mut().storage, cc_id.clone(), message).unwrap();
//
//         let msg = ExecuteMsg::Execute {
//             cc_id,
//             payload: [4, 5, 6].into(),
//         };
//
//         let err = execute(deps.as_mut(), env, info, msg).unwrap_err();
//         assert!(err_contains!(err.report, Error, Error::PayloadHashMismatch));
//     }
//
//     #[test]
//     #[should_panic(expected = "should match chain name")]
//     fn receive_messages_wrong_chain() {
//         let (mut deps, _, _) = setup();
//
//         let mut message = dummy_message();
//         message.destination_chain = "wrong-chain".parse().unwrap();
//
//         let msg = ExecuteMsg::RouteMessages(vec![message]);
//         let info = mock_info(ROUTER, &[]);
//
//         // This should panic because the destination chain doesn't match the gateway's chain name
//         execute(deps.as_mut(), mock_env(), info, msg).unwrap();
//     }
// }

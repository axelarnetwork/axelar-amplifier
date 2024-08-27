use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
use cosmwasm_std::{
    Addr, Api, Event, HexBinary, QuerierWrapper, Response, Storage, Uint256, WasmMsg,
};
use error_stack::{report, Result, ResultExt};
use router_api::client::Router;
use router_api::{Address, ChainName, CrossChainId, Message};
use sha3::{Digest, Keccak256};

use crate::contract::Error;
use crate::events::AxelarnetGatewayEvent;
use crate::executable::AxelarExecutableClient;
use crate::state::{self};

#[allow(clippy::too_many_arguments)]
pub fn call_contract(
    store: &mut dyn Storage,
    block_height: u64,
    router: &Router,
    chain_name: ChainName,
    sender: Addr,
    destination_chain: ChainName,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let counter = state::increment_msg_counter(store).change_context(Error::InvalidStoreAccess)?;

    // TODO: Retrieve the actual tx hash from core, since cosmwasm doesn't provide it. Use the block height as the placeholder in the meantime.
    let message_id = HexTxHashAndEventIndex {
        tx_hash: Uint256::from(block_height).to_be_bytes(),
        event_index: counter,
    }
    .into();

    let cc_id = CrossChainId {
        source_chain: chain_name.into(),
        message_id,
    };

    let payload_hash = Keccak256::digest(payload.as_slice()).into();

    let msg = Message {
        cc_id: cc_id.clone(),
        source_address: Address::try_from(sender.into_string())
            .expect("failed to convert sender address"),
        destination_chain,
        destination_address,
        payload_hash,
    };

    state::save_sent_msg(store, cc_id, &msg).change_context(Error::InvalidStoreAccess)?;

    let (wasm_msg, events) = route(router, vec![msg.clone()])?;

    Ok(Response::new()
        .add_message(wasm_msg)
        .add_event(AxelarnetGatewayEvent::ContractCalled { msg, payload }.into())
        .add_events(events))
}

// Because the messages came from the router, we can assume they are already verified
pub fn receive_messages(
    store: &mut dyn Storage,
    chain_name: ChainName,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    for msg in msgs.iter() {
        if chain_name != msg.destination_chain {
            panic!("message destination chain should match chain name in the gateway")
        }

        state::save_received_msg(store, msg.cc_id.clone(), msg.clone())
            .change_context(Error::SaveOutgoingMessage)?;
    }

    Ok(Response::new().add_events(
        msgs.into_iter()
            .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into()),
    ))
}

pub fn send_messages(
    store: &mut dyn Storage,
    router: &Router,
    msgs: Vec<Message>,
) -> Result<Response, Error> {
    for msg in msgs.iter() {
        let stored_msg = state::may_load_sent_msg(store, &msg.cc_id)
            .change_context(Error::InvalidStoreAccess)?;

        match stored_msg {
            Some(message) if msg != &message => {
                Err(report!(Error::MessageMismatch(msg.cc_id.clone())))
            }
            Some(_) => Ok(()),
            None => Err(report!(Error::MessageNotFound(msg.cc_id.clone()))),
        }?
    }

    let (wasm_msg, events) = route(router, msgs)?;

    Ok(Response::new().add_message(wasm_msg).add_events(events))
}

fn route(
    router: &Router,
    msgs: Vec<Message>,
) -> Result<(WasmMsg, impl IntoIterator<Item = Event>), Error> {
    Ok((
        router.route(msgs.clone()).ok_or(Error::RoutingFailed)?,
        msgs.into_iter()
            .map(|msg| AxelarnetGatewayEvent::Routing { msg }.into()),
    ))
}

pub fn execute(
    store: &mut dyn Storage,
    api: &dyn Api,
    querier: QuerierWrapper,
    cc_id: CrossChainId,
    payload: HexBinary,
) -> Result<Response, Error> {
    let msg = state::set_msg_as_executed(store, cc_id.clone())
        .change_context(Error::SetMessageStatusExecutedFailed(cc_id))?;

    let payload_hash: [u8; 32] = Keccak256::digest(payload.as_slice()).into();
    if payload_hash != msg.payload_hash {
        return Err(report!(Error::PayloadHashMismatch));
    }

    let destination_contract = api
        .addr_validate(&msg.destination_address)
        .change_context(Error::InvalidAddress(msg.destination_address.to_string()))?;

    let executable: AxelarExecutableClient =
        client::Client::new(querier, destination_contract).into();

    // Call the destination contract
    // Apps are required to expose AxelarExecutableMsg::Execute interface
    Ok(Response::new()
        .add_message(executable.execute(msg.cc_id.clone(), msg.source_address.clone(), payload))
        .add_event(AxelarnetGatewayEvent::MessageExecuted { msg }.into()))
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::err_contains;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{Addr, CosmosMsg, Empty, Env, MessageInfo, OwnedDeps};
    use router_api::{ChainName, CrossChainId, Message};

    use super::*;
    use crate::contract::{execute, instantiate};
    use crate::msg::{ExecuteMsg, InstantiateMsg};
    use crate::state::{self, MessageStatus};

    const CHAIN: &str = "chain";
    const SOURCE_CHAIN: &str = "source-chain";
    const ROUTER: &str = "router";
    const PAYLOAD: [u8; 3] = [1, 2, 3];
    const SENDER: &str = "sender";

    fn setup() -> (
        OwnedDeps<MockStorage, MockApi, MockQuerier, Empty>,
        Env,
        MessageInfo,
    ) {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(SENDER, &[]);

        let chain_name: ChainName = CHAIN.parse().unwrap();
        let router = Addr::unchecked(ROUTER);

        let msg = InstantiateMsg {
            chain_name: chain_name.clone(),
            router_address: router.to_string(),
        };

        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        (deps, env, info)
    }

    fn dummy_message() -> Message {
        Message {
            cc_id: CrossChainId::new(SOURCE_CHAIN, "message-id").unwrap(),
            source_address: "source-address".parse().unwrap(),
            destination_chain: CHAIN.parse().unwrap(),
            destination_address: "destination-address".parse().unwrap(),
            payload_hash: Keccak256::digest(PAYLOAD).into(),
        }
    }

    #[test]
    fn call_contract_and_send_message() {
        let (mut deps, env, info) = setup();

        let expected_message_id = HexTxHashAndEventIndex {
            tx_hash: Uint256::from(env.block.height).to_be_bytes(),
            event_index: 1,
        };
        let expected_cc_id = CrossChainId::new(CHAIN, expected_message_id).unwrap();
        let message = Message {
            cc_id: expected_cc_id.clone(),
            source_address: info.sender.clone().into_string().parse().unwrap(),
            destination_chain: "destination-chain".parse().unwrap(),
            destination_address: "destination-address".parse().unwrap(),
            payload_hash: Keccak256::digest(PAYLOAD).into(),
        };

        let msg = ExecuteMsg::CallContract {
            destination_chain: message.destination_chain.clone(),
            destination_address: message.destination_address.clone(),
            payload: PAYLOAD.into(),
        };

        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        let sent_message = state::may_load_sent_msg(deps.as_mut().storage, &expected_cc_id)
            .unwrap()
            .unwrap();
        assert_eq!(sent_message, message);

        let router: Router = Router {
            address: Addr::unchecked(ROUTER),
        };
        assert_eq!(res.messages.len(), 1);
        assert_eq!(
            res.messages[0].msg,
            CosmosMsg::Wasm(router.route(vec![message.clone()]).unwrap())
        );

        // Re-route the message again
        let msg = ExecuteMsg::RouteMessages(vec![message.clone()]);
        let res = execute(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.messages.len(), 1);
        assert_eq!(
            res.messages[0].msg,
            CosmosMsg::Wasm(router.route(vec![message]).unwrap())
        );
    }

    #[test]
    fn route_messages_from_router() {
        let (mut deps, env, _) = setup();

        let message = dummy_message();
        let msg = ExecuteMsg::RouteMessages(vec![message.clone()]);

        // Execute RouteMessages as if it's coming from the router
        let info = mock_info(ROUTER, &[]);
        execute(deps.as_mut(), env, info, msg).unwrap();

        // Check that the message was saved as received
        let received_message = state::may_load_received_msg(deps.as_mut().storage, &message.cc_id)
            .unwrap()
            .unwrap();
        assert_eq!(received_message.msg, message);
        assert!(matches!(received_message.status, MessageStatus::Approved));
    }

    #[test]
    fn execute_message() {
        let (mut deps, env, info) = setup();

        let message = dummy_message();
        let cc_id = message.cc_id.clone();

        // Save the message as received
        state::save_received_msg(deps.as_mut().storage, cc_id.clone(), message).unwrap();

        let msg = ExecuteMsg::Execute {
            cc_id: cc_id.clone(),
            payload: PAYLOAD.into(),
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap();

        // Check that a message was sent to the destination contract
        assert_eq!(res.messages.len(), 1);

        // Check that the message status was updated to Executed
        let executed_message = state::may_load_received_msg(deps.as_mut().storage, &cc_id)
            .unwrap()
            .unwrap();
        assert!(matches!(executed_message.status, MessageStatus::Executed));
    }

    #[test]
    fn execute_not_found() {
        let (mut deps, env, info) = setup();

        let cc_id = CrossChainId::new(SOURCE_CHAIN, "message-id").unwrap();
        let msg = ExecuteMsg::Execute {
            cc_id: cc_id.clone(),
            payload: PAYLOAD.into(),
        };

        let err = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert!(err_contains!(
            err.report,
            state::Error,
            state::Error::MessageNotApproved(..)
        ));
        assert!(err_contains!(
            err.report,
            Error,
            Error::SetMessageStatusExecutedFailed(..)
        ));
    }

    #[test]
    fn execute_already_executed() {
        let (mut deps, env, info) = setup();

        let message = dummy_message();
        let cc_id = message.cc_id.clone();

        // Save the message as already executed
        state::save_received_msg(deps.as_mut().storage, cc_id.clone(), message).unwrap();
        state::set_msg_as_executed(deps.as_mut().storage, cc_id.clone()).unwrap();

        let msg = ExecuteMsg::Execute {
            cc_id,
            payload: PAYLOAD.into(),
        };

        let err = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert!(err_contains!(
            err.report,
            state::Error,
            state::Error::MessageAlreadyExecuted(..)
        ));
        assert!(err_contains!(
            err.report,
            Error,
            Error::SetMessageStatusExecutedFailed(..)
        ));
    }

    #[test]
    fn execute_payload_mismatch() {
        let (mut deps, env, info) = setup();

        let message = dummy_message();
        let cc_id = message.cc_id.clone();

        state::save_received_msg(deps.as_mut().storage, cc_id.clone(), message).unwrap();

        let msg = ExecuteMsg::Execute {
            cc_id,
            payload: [4, 5, 6].into(),
        };

        let err = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert!(err_contains!(err.report, Error, Error::PayloadHashMismatch));
    }

    #[test]
    #[should_panic(expected = "should match chain name")]
    fn receive_messages_wrong_chain() {
        let (mut deps, _, _) = setup();

        let mut message = dummy_message();
        message.destination_chain = "wrong-chain".parse().unwrap();

        let msg = ExecuteMsg::RouteMessages(vec![message]);
        let info = mock_info(ROUTER, &[]);

        // This should panic because the destination chain doesn't match the gateway's chain name
        execute(deps.as_mut(), mock_env(), info, msg).unwrap();
    }
}

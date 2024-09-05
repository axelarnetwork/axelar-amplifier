use assert_ok::assert_ok;
use axelar_wasm_std::response::inspect_response_msg;
use axelar_wasm_std::{assert_err_contains, permission_control};
use axelarnet_gateway::msg::ExecuteMsg as AxelarnetGatewayExecuteMsg;
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use cosmwasm_std::HexBinary;
use interchain_token_service::contract::{self, ExecuteError};
use interchain_token_service::events::Event;
use interchain_token_service::msg::ExecuteMsg;
use interchain_token_service::{ItsHubMessage, ItsMessage, TokenId, TokenManagerType};
use router_api::{Address, ChainName, CrossChainId};
use utils::TestMessage;

mod utils;

#[test]
fn register_deregister_its_address_succeeds() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainName = "ethereum".parse().unwrap();
    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    assert_ok!(utils::register_its_address(
        deps.as_mut(),
        chain.clone(),
        address.clone()
    ));

    let res = assert_ok!(utils::query_its_address(deps.as_ref(), chain.clone()));
    assert_eq!(res, Some(address));

    assert_ok!(utils::deregister_its_address(deps.as_mut(), chain.clone()));

    let res = assert_ok!(utils::query_its_address(deps.as_ref(), chain.clone()));
    assert_eq!(res, None);
}

#[test]
fn execute_its_hub_message_succeeds() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        router_message,
        source_its_chain,
        source_its_address,
        destination_its_chain,
        destination_its_address,
        ..
    } = TestMessage::dummy();

    utils::register_its_address(
        deps.as_mut(),
        source_its_chain.clone(),
        source_its_address.clone(),
    )
    .unwrap();
    utils::register_its_address(
        deps.as_mut(),
        destination_its_chain.clone(),
        destination_its_address.clone(),
    )
    .unwrap();

    let token_id = TokenId::new([1; 32]);
    let test_its_messages = vec![
        ItsMessage::InterchainTransfer {
            token_id: token_id.clone(),
            source_address: HexBinary::from([1; 32]),
            destination_address: HexBinary::from([2; 32]),
            amount: 1u64.into(),
            data: HexBinary::from([1, 2, 3, 4]),
        },
        ItsMessage::DeployInterchainToken {
            token_id: token_id.clone(),
            name: "Test".into(),
            symbol: "TST".into(),
            decimals: 18,
            minter: HexBinary::from([1; 32]),
        },
        ItsMessage::DeployTokenManager {
            token_id: token_id.clone(),
            token_manager_type: TokenManagerType::MintBurn,
            params: HexBinary::from([1, 2, 3, 4]),
        },
    ];

    let responses: Vec<_> = test_its_messages
        .into_iter()
        .map(|its_message| {
            let hub_message = ItsHubMessage::SendToHub {
                destination_chain: destination_its_chain.clone(),
                message: its_message,
            };
            let payload = hub_message.clone().abi_encode();
            let receive_payload = ItsHubMessage::ReceiveFromHub {
                source_chain: source_its_chain.clone().into(),
                message: hub_message.message().clone(),
            }
            .abi_encode();

            let response = assert_ok!(utils::execute(
                deps.as_mut(),
                router_message.cc_id.clone(),
                source_its_address.clone(),
                payload,
            ));
            let msg: AxelarnetGatewayExecuteMsg =
                assert_ok!(inspect_response_msg(response.clone()));
            let expected_msg = AxelarnetGatewayExecuteMsg::CallContract {
                destination_chain: destination_its_chain.clone(),
                destination_address: destination_its_address.clone(),
                payload: receive_payload,
            };
            assert_eq!(msg, expected_msg);

            let expected_event = Event::ItsMessageReceived {
                cc_id: router_message.cc_id.clone(),
                destination_chain: destination_its_chain.clone(),
                message: hub_message.message().clone(),
            };
            assert_eq!(
                response.events,
                vec![cosmwasm_std::Event::from(expected_event)]
            );

            response
        })
        .collect();

    goldie::assert_json!(responses);
}

#[test]
fn execute_its_when_not_gateway_sender_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let result = contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info("not-gateway", &[]),
        ExecuteMsg::Execute(axelarnet_gateway::AxelarExecutableMsg {
            cc_id: CrossChainId::new("source", "hash").unwrap(),
            source_address: "source".parse().unwrap(),
            payload: HexBinary::from([]),
        }),
    );
    assert_err_contains!(
        result,
        permission_control::Error,
        permission_control::Error::AddressNotWhitelisted { .. }
    );
}

#[test]
fn execute_message_when_unknown_source_address_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        hub_message,
        router_message,
        source_its_chain,
        source_its_address,
        ..
    } = TestMessage::dummy();

    utils::register_its_address(deps.as_mut(), source_its_chain, source_its_address).unwrap();

    let unknown_address: Address = "unknown-address".parse().unwrap();
    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id.clone(),
        unknown_address,
        hub_message.abi_encode(),
    );
    assert_err_contains!(result, ExecuteError, ExecuteError::UnknownItsAddress { .. });
}

#[test]
fn execute_message_when_invalid_payload_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        router_message,
        source_its_chain,
        source_its_address,
        ..
    } = TestMessage::dummy();

    utils::register_its_address(deps.as_mut(), source_its_chain, source_its_address.clone())
        .unwrap();

    let invalid_payload = HexBinary::from_hex("1234").unwrap();
    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_address,
        invalid_payload,
    );
    assert_err_contains!(result, ExecuteError, ExecuteError::InvalidPayload);
}

#[test]
fn execute_message_when_unknown_chain_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        hub_message,
        router_message,
        source_its_chain,
        source_its_address,
        destination_its_chain,
        ..
    } = TestMessage::dummy();

    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_address.clone(),
        hub_message.clone().abi_encode(),
    );
    assert_err_contains!(result, ExecuteError, ExecuteError::UnknownChain(chain) if chain == &source_its_chain);

    utils::register_its_address(deps.as_mut(), source_its_chain, source_its_address.clone())
        .unwrap();

    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id,
        source_its_address,
        hub_message.abi_encode(),
    );
    assert_err_contains!(result, ExecuteError, ExecuteError::UnknownChain(chain) if chain == &destination_its_chain);
}

#[test]
fn execute_message_when_invalid_message_type_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        hub_message,
        router_message,
        source_its_chain,
        source_its_address,
        ..
    } = TestMessage::dummy();

    utils::register_its_address(
        deps.as_mut(),
        source_its_chain.clone(),
        source_its_address.clone(),
    )
    .unwrap();

    let invalid_hub_message = ItsHubMessage::ReceiveFromHub {
        source_chain: source_its_chain.into(),
        message: hub_message.message().clone(),
    };
    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id,
        source_its_address,
        invalid_hub_message.abi_encode(),
    );
    assert_err_contains!(result, ExecuteError, ExecuteError::InvalidMessageType);
}

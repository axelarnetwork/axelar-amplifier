use assert_ok::assert_ok;
use axelar_wasm_std::response::inspect_response_msg;
use axelarnet_gateway::msg::ExecuteMsg as AxelarnetGatewayExecuteMsg;
use cosmwasm_std::testing::mock_dependencies;
use interchain_token_service::events::Event;
use interchain_token_service::ItsHubMessage;
use router_api::{Address, ChainName};
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
fn execute_interchain_transfer_succeeds() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        hub_message,
        router_message,
        source_its_chain,
        source_its_address,
        destination_its_chain,
        destination_its_address,
    } = TestMessage::dummy();

    let payload = hub_message.clone().abi_encode();
    let receive_payload = ItsHubMessage::ReceiveFromHub {
        source_chain: source_its_chain.clone(),
        message: hub_message.message().clone(),
    }
    .abi_encode();

    assert_ok!(utils::register_its_address(
        deps.as_mut(),
        source_its_chain.clone().to_string().parse().unwrap(),
        source_its_address.clone(),
    ));
    assert_ok!(utils::register_its_address(
        deps.as_mut(),
        destination_its_chain.clone().to_string().parse().unwrap(),
        destination_its_address.clone(),
    ));

    let response = utils::execute(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_address,
        payload,
    )
    .unwrap();
    let msg: AxelarnetGatewayExecuteMsg = assert_ok!(inspect_response_msg(response.clone()));
    let expected_msg = AxelarnetGatewayExecuteMsg::CallContract {
        destination_chain: destination_its_chain.clone(),
        destination_address: destination_its_address,
        payload: receive_payload,
    };
    assert_eq!(msg, expected_msg);

    let expected_event = Event::ItsMessageReceived {
        cc_id: router_message.cc_id,
        destination_chain: destination_its_chain,
        message: hub_message.message().clone(),
    };
    assert_eq!(
        response.events,
        vec![cosmwasm_std::Event::from(expected_event)]
    );

    goldie::assert_json!(response);
}

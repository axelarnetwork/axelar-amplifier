use axelar_wasm_std::msg::inspect_response_msg;
use axelarnet_gateway::msg::ExecuteMsg as AxelarnetGatewayExecuteMsg;
use cosmwasm_std::testing::{mock_dependencies, mock_env};
use cosmwasm_std::{from_json, HexBinary};
use interchain_token_service::contract::query;
use interchain_token_service::msg::QueryMsg;
use interchain_token_service::{ItsHubMessage, ItsMessage, TokenId};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

mod utils;

#[test]
fn set_its_address() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainName = "ethereum".parse().unwrap();
    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    let res = utils::set_its_address(deps.as_mut(), chain.clone(), address.clone());
    assert!(res.is_ok());

    let query_msg = QueryMsg::ItsAddress { chain };
    let res: Option<Address> =
        from_json(query(deps.as_ref(), mock_env(), query_msg).unwrap()).unwrap();

    assert_eq!(res, Some(address));
}

#[test]
fn remove_its_address() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainName = "ethereum".parse().unwrap();
    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    utils::set_its_address(deps.as_mut(), chain.clone(), address).unwrap();

    let res = utils::remove_its_address(deps.as_mut(), chain.clone());
    assert!(res.is_ok());

    let query_msg = QueryMsg::ItsAddress { chain };
    let res: Option<Address> =
        from_json(query(deps.as_ref(), mock_env(), query_msg).unwrap()).unwrap();

    assert_eq!(res, None);
}

#[test]
fn execute() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let source_its_address: Address = "source-its-contract".parse().unwrap();
    let destination_its_address: Address = "destination-its-contract".parse().unwrap();

    let token_id = TokenId::new([0u8; 32]);
    let source_address = HexBinary::from(b"source-caller");
    let destination_address = HexBinary::from(b"destination-recipient");
    let amount = 1000u128.into();
    let data = HexBinary::from(b"data");

    let its_message = ItsMessage::InterchainTransfer {
        token_id,
        source_address: source_address.clone(),
        destination_address,
        amount,
        data,
    };

    let source_its_chain: ChainNameRaw = "optimism".parse().unwrap();
    let destination_its_chain: ChainName = "ethereum".parse().unwrap();
    let hub_message = ItsHubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message: its_message.clone(),
    };

    let payload = hub_message.abi_encode();
    let cc_id = CrossChainId::new(source_its_chain.clone(), "message-id").unwrap();

    utils::set_its_address(
        deps.as_mut(),
        source_its_chain.clone().to_string().parse().unwrap(),
        source_its_address.clone(),
    )
    .unwrap();
    utils::set_its_address(
        deps.as_mut(),
        destination_its_chain.clone().to_string().parse().unwrap(),
        destination_its_address.clone(),
    )
    .unwrap();

    let res = utils::execute(deps.as_mut(), cc_id, source_its_address, payload);
    assert!(res.is_ok());

    let response = res.unwrap();
    assert_eq!(response.messages.len(), 1);

    let msg = inspect_response_msg::<AxelarnetGatewayExecuteMsg>(response);
    assert!(msg.is_ok());

    match msg.unwrap() {
        AxelarnetGatewayExecuteMsg::CallContract {
            destination_chain,
            destination_address,
            payload,
        } => {
            assert_eq!(destination_chain, destination_its_chain);
            assert_eq!(destination_address, destination_its_address);

            let hub_message = ItsHubMessage::abi_decode(&payload);
            assert!(hub_message.is_ok());

            match hub_message.unwrap() {
                ItsHubMessage::ReceiveFromHub {
                    source_chain,
                    message,
                } => {
                    assert_eq!(source_chain, source_its_chain);
                    assert_eq!(message, its_message);
                }
                _ => panic!("Expected ReceiveFromHub message"),
            }
        }
        _ => panic!("Expected CallContract message"),
    }
}

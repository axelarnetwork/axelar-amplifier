use std::str::FromStr;

use assert_ok::assert_ok;
use axelar_wasm_std::response::inspect_response_msg;
use axelar_wasm_std::{assert_err_contains, nonempty, permission_control};
use axelarnet_gateway::msg::ExecuteMsg as AxelarnetGatewayExecuteMsg;
use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
use cosmwasm_std::{HexBinary, Uint128, Uint256};
use interchain_token_service::contract::{self, ExecuteError};
use interchain_token_service::events::Event;
use interchain_token_service::msg::{self, ExecuteMsg, TruncationConfig};
use interchain_token_service::{
    DeployInterchainToken, HubMessage, InterchainTransfer, LinkToken, RegisterTokenMetadata,
    TokenId, TokenSupply,
};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};
use serde_json::json;
use utils::{make_deps, params, register_chains, TestMessage};

mod utils;

use crate::contract::Error;

#[test]
fn register_update_its_contract_succeeds() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainNameRaw = "ethereum".parse().unwrap();
    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    assert_ok!(utils::register_chain(
        deps.as_mut(),
        chain.clone(),
        address.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX
    ));

    let chain_config = assert_ok!(utils::query_its_chain(deps.as_ref(), chain.clone()));
    assert_eq!(chain_config.unwrap().its_edge_contract, address);

    let new_address: Address = "0x9999999990123456789012345678901234567890"
        .parse()
        .unwrap();
    assert_ok!(utils::update_chain(
        deps.as_mut(),
        chain.clone(),
        new_address.clone(),
        Uint128::MAX.try_into().unwrap(),
        18u8
    ));
    let res = assert_ok!(utils::query_its_chain(deps.as_ref(), chain.clone()));
    assert_eq!(res.unwrap().its_edge_contract, new_address);
}

#[test]
fn reregistering_same_chain_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainNameRaw = "ethereum".parse().unwrap();
    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    assert_ok!(utils::register_chain(
        deps.as_mut(),
        chain.clone(),
        address.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX
    ));

    assert_err_contains!(
        utils::register_chain(
            deps.as_mut(),
            chain.clone(),
            address.clone(),
            Uint256::MAX.try_into().unwrap(),
            u8::MAX
        ),
        Error,
        Error::RegisterChains
    );
}

#[test]
fn update_unknown_chain_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainNameRaw = "ethereum".parse().unwrap();

    assert_err_contains!(
        utils::update_chain(
            deps.as_mut(),
            chain,
            "0x1234567890123456789012345678901234567890"
                .parse()
                .unwrap(),
            Uint256::MAX.try_into().unwrap(),
            u8::MAX
        ),
        Error,
        Error::UpdateChain
    );
}

#[test]
fn register_multiple_chains_succeeds() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();
    let chains: Vec<msg::ChainConfig> = (0..10)
        .map(|i| msg::ChainConfig {
            chain: i.to_string().parse().unwrap(),
            its_edge_contract: i.to_string().parse().unwrap(),
            truncation: TruncationConfig {
                max_decimals_when_truncating: 18u8,
                max_uint: Uint256::MAX.try_into().unwrap(),
            },
        })
        .collect();
    assert_ok!(register_chains(deps.as_mut(), chains.clone()));

    for chain in chains {
        let res = assert_ok!(utils::query_its_chain(deps.as_ref(), chain.chain.clone()));
        assert_eq!(res.unwrap().its_edge_contract, chain.its_edge_contract);
    }
}

#[test]
fn register_multiple_chains_fails_if_one_invalid() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();
    let chains: Vec<msg::ChainConfig> = (0..10)
        .map(|i| msg::ChainConfig {
            chain: i.to_string().parse().unwrap(),
            its_edge_contract: i.to_string().parse().unwrap(),
            truncation: TruncationConfig {
                max_decimals_when_truncating: 18u8,
                max_uint: Uint256::MAX.try_into().unwrap(),
            },
        })
        .collect();
    assert_ok!(register_chains(deps.as_mut(), chains[0..1].to_vec()));
    assert_err_contains!(
        register_chains(deps.as_mut(), chains.clone()),
        Error,
        Error::RegisterChains
    );
}

#[test]
fn execute_hub_message_succeeds() {
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_chain,
            source_its_contract,
            destination_its_chain,
            destination_its_contract,
            ..
        },
    ) = utils::setup();

    let test_messages = vec![
        DeployInterchainToken {
            token_id: TokenId::new([1; 32]),
            name: "Test".try_into().unwrap(),
            symbol: "TST".try_into().unwrap(),
            decimals: 18,
            minter: Some(HexBinary::from([1; 32]).try_into().unwrap()),
        }
        .into(),
        InterchainTransfer {
            token_id: TokenId::new([1; 32]),
            source_address: HexBinary::from([1; 32]).try_into().unwrap(),
            destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
            amount: 1u64.try_into().unwrap(),
            data: Some(HexBinary::from([1, 2, 3, 4]).try_into().unwrap()),
        }
        .into(),
    ];

    let responses: Vec<_> = test_messages
        .into_iter()
        .map(|message| {
            let hub_message = HubMessage::SendToHub {
                destination_chain: destination_its_chain.clone(),
                message,
            };
            let receive_payload = HubMessage::ReceiveFromHub {
                source_chain: source_its_chain.clone(),
                message: hub_message.message().clone(),
            }
            .abi_encode();

            let response = assert_ok!(utils::execute_hub_message(
                deps.as_mut(),
                router_message.cc_id.clone(),
                source_its_contract.clone(),
                hub_message.clone(),
            ));
            let msg: AxelarnetGatewayExecuteMsg =
                assert_ok!(inspect_response_msg(response.clone()));
            let expected_msg = AxelarnetGatewayExecuteMsg::CallContract {
                destination_chain: ChainName::try_from(destination_its_chain.to_string()).unwrap(),
                destination_address: destination_its_contract.clone(),
                payload: receive_payload,
            };
            assert_eq!(msg, expected_msg);

            let expected_event = Event::MessageReceived {
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
fn execute_message_interchain_transfer_should_scale_custom_tokens_when_decimals_are_different() {
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_contract,
            source_its_chain,
            destination_its_chain,
            destination_its_contract,
            ..
        },
    ) = utils::setup_with_chain_configs(
        Uint256::MAX.try_into().unwrap(),
        6,
        u64::MAX.try_into().unwrap(),
        6,
    );
    let token_id = TokenId::new([1; 32]);
    let hub_message = HubMessage::RegisterTokenMetadata(RegisterTokenMetadata {
        decimals: 6,
        token_address: HexBinary::from([1; 32]).try_into().unwrap(),
    });
    let cc_id = CrossChainId {
        source_chain: source_its_chain.clone(),
        message_id: router_message.cc_id.message_id.clone(),
    };
    let source_register_token_response = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        cc_id,
        source_its_contract.clone(),
        hub_message,
    ));

    let hub_message = HubMessage::RegisterTokenMetadata(RegisterTokenMetadata {
        decimals: 18,
        token_address: HexBinary::from([1; 32]).try_into().unwrap(),
    });
    let cc_id = CrossChainId {
        source_chain: destination_its_chain.clone(),
        message_id: router_message.cc_id.message_id.clone(),
    };
    let destination_register_token_response = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        cc_id,
        destination_its_contract.clone(),
        hub_message,
    ));

    let hub_message = HubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message: LinkToken {
            token_id,
            token_manager_type: Uint256::zero(),
            source_token_address: HexBinary::from([1; 32]).try_into().unwrap(),
            destination_token_address: HexBinary::from([1; 32]).try_into().unwrap(),
            params: None,
        }
        .into(),
    };

    let cc_id = CrossChainId {
        source_chain: source_its_chain.clone(),
        message_id: router_message.cc_id.message_id.clone(),
    };
    let link_token_response = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        cc_id,
        source_its_contract.clone(),
        hub_message,
    ));

    // send from source to destination
    let transfer = InterchainTransfer {
        token_id,
        source_address: HexBinary::from([1; 32]).try_into().unwrap(),
        destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
        amount: Uint256::from_u128(1_000_000u128).try_into().unwrap(),
        data: None,
    };
    let hub_message = HubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message: transfer.into(),
    };
    let response_to_destination = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract,
        hub_message,
    ));

    // send back from destination to source
    let transfer = InterchainTransfer {
        token_id,
        source_address: HexBinary::from([2; 32]).try_into().unwrap(),
        destination_address: HexBinary::from([1; 32]).try_into().unwrap(),
        amount: Uint256::from_u128(1_000_000_000_000_000_000u128)
            .try_into()
            .unwrap(),
        data: None,
    };
    let mut cc_id = router_message.cc_id.clone();
    cc_id.source_chain = destination_its_chain.clone();
    let hub_message = HubMessage::SendToHub {
        destination_chain: source_its_chain,
        message: transfer.into(),
    };
    let response_to_source = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        cc_id,
        destination_its_contract,
        hub_message,
    ));

    goldie::assert_json!(json!({"response_to_destination": response_to_destination,
        "response_to_source": response_to_source,
        "source_register_token_response": source_register_token_response,
        "destination_register_token_response": destination_register_token_response,
        "link_token_response" : link_token_response}));
}

#[test]
fn execute_message_interchain_transfer_should_scale_the_amount_when_source_decimals_are_different()
{
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_contract,
            source_its_chain,
            destination_its_chain,
            destination_its_contract,
            ..
        },
    ) = utils::setup_with_chain_configs(
        Uint256::MAX.try_into().unwrap(),
        6,
        u64::MAX.try_into().unwrap(),
        6,
    );
    let token_id = TokenId::new([1; 32]);
    let deploy_token = DeployInterchainToken {
        token_id,
        name: "Test".try_into().unwrap(),
        symbol: "TST".try_into().unwrap(),
        decimals: 18,
        minter: None,
    }
    .into();
    let hub_message = HubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message: deploy_token,
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        hub_message,
    ));

    // send from source to destination
    let transfer = InterchainTransfer {
        token_id,
        source_address: HexBinary::from([1; 32]).try_into().unwrap(),
        destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
        amount: Uint256::from_u128(1_000_000_000_000_000_000u128)
            .try_into()
            .unwrap(),
        data: None,
    };
    let hub_message = HubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message: transfer.into(),
    };
    let response_to_destination = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract,
        hub_message,
    ));

    // send back from destination to source
    let transfer = InterchainTransfer {
        token_id,
        source_address: HexBinary::from([2; 32]).try_into().unwrap(),
        destination_address: HexBinary::from([1; 32]).try_into().unwrap(),
        amount: Uint256::from_u128(1_000_000u128).try_into().unwrap(),
        data: None,
    };
    let mut cc_id = router_message.cc_id.clone();
    cc_id.source_chain = destination_its_chain.clone();
    let hub_message = HubMessage::SendToHub {
        destination_chain: source_its_chain,
        message: transfer.into(),
    };
    let response_to_source = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        cc_id,
        destination_its_contract,
        hub_message,
    ));

    goldie::assert_json!(
        json!({"response_to_destination": response_to_destination, "response_to_source": response_to_source})
    );
}

#[test]
fn execute_message_interchain_transfer_should_scale_correctly_in_3_chain_cycle() {
    let TestMessage {
        source_its_contract,
        ..
    } = TestMessage::dummy();
    let configs = vec![
        (
            "ethereum".parse().unwrap(),
            source_its_contract.clone(),
            Uint256::MAX.try_into().unwrap(),
            u8::MAX,
        ),
        (
            "stellar".parse().unwrap(),
            source_its_contract.clone(),
            Uint256::from(u128::MAX).try_into().unwrap(),
            12,
        ),
        (
            "sui".parse().unwrap(),
            source_its_contract.clone(),
            Uint256::from(u64::MAX).try_into().unwrap(),
            6,
        ),
    ];

    let (mut deps, TestMessage { router_message, .. }) =
        utils::setup_multiple_chains(configs.clone());
    let token_id = TokenId::new([1; 32]);
    let deploy_token = DeployInterchainToken {
        token_id,
        name: "Test".try_into().unwrap(),
        symbol: "TST".try_into().unwrap(),
        decimals: 18,
        minter: None,
    };
    let hub_message = HubMessage::SendToHub {
        destination_chain: configs[1].0.clone(),
        message: deploy_token.clone().into(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId {
            source_chain: configs[0].0.clone(),
            message_id: router_message.cc_id.message_id.clone()
        },
        source_its_contract.clone(),
        hub_message,
    ));

    let hub_message = HubMessage::SendToHub {
        destination_chain: configs[2].0.clone(),
        message: deploy_token.clone().into(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId {
            source_chain: configs[0].0.clone(),
            message_id: router_message.cc_id.message_id.clone()
        },
        source_its_contract.clone(),
        hub_message,
    ));

    let amount: nonempty::Uint256 = Uint256::from_u128(1000000000000000000u128)
        .try_into()
        .unwrap();

    // send from chain 0 to chain 1
    let transfer = InterchainTransfer {
        token_id,
        source_address: HexBinary::from([1; 32]).try_into().unwrap(),
        destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
        amount,
        data: None,
    };
    let hub_message = HubMessage::SendToHub {
        destination_chain: configs[1].0.clone(),
        message: transfer.into(),
    };

    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId {
            source_chain: configs[0].0.clone(),
            message_id: router_message.cc_id.message_id.clone()
        },
        source_its_contract.clone(),
        hub_message,
    ));

    let scaling_factor = Uint256::from_u128(10)
        .checked_pow(deploy_token.decimals.abs_diff(configs[1].3).into())
        .unwrap();
    let scaled_amount = amount.clone().checked_div(scaling_factor).unwrap();

    // send back from destination to source
    let transfer = InterchainTransfer {
        token_id,
        source_address: HexBinary::from([2; 32]).try_into().unwrap(),
        destination_address: HexBinary::from([1; 32]).try_into().unwrap(),
        amount: scaled_amount.try_into().unwrap(),
        data: None,
    };

    let hub_message = HubMessage::SendToHub {
        destination_chain: configs[2].0.clone(),
        message: transfer.into(),
    };

    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId {
            source_chain: configs[1].0.clone(),
            message_id: router_message.cc_id.message_id.clone()
        },
        source_its_contract.clone(),
        hub_message,
    ));

    let scaling_factor = Uint256::from_u128(10)
        .checked_pow(deploy_token.decimals.abs_diff(configs[2].3).into())
        .unwrap();
    let scaled_amount = amount.clone().checked_div(scaling_factor).unwrap();

    // send back from destination to source
    let transfer = InterchainTransfer {
        token_id,
        source_address: HexBinary::from([2; 32]).try_into().unwrap(),
        destination_address: HexBinary::from([1; 32]).try_into().unwrap(),
        amount: scaled_amount.try_into().unwrap(),
        data: None,
    };

    let hub_message = HubMessage::SendToHub {
        destination_chain: configs[0].0.clone(),
        message: transfer.into(),
    };

    let response_to_destination = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId {
            source_chain: configs[2].0.clone(),
            message_id: router_message.cc_id.message_id.clone()
        },
        source_its_contract,
        hub_message,
    ));

    goldie::assert_json!(response_to_destination);
}

#[test]
fn execute_message_interchain_transfer_should_scale_correctly_in_3_chain_cycle_with_dust() {
    let TestMessage {
        source_its_contract,
        ..
    } = TestMessage::dummy();
    let configs = vec![
        (
            "ethereum".parse().unwrap(),
            source_its_contract.clone(),
            Uint256::MAX.try_into().unwrap(),
            u8::MAX,
        ),
        (
            "stellar".parse().unwrap(),
            source_its_contract.clone(),
            Uint256::from(u128::MAX).try_into().unwrap(),
            12,
        ),
        (
            "sui".parse().unwrap(),
            source_its_contract.clone(),
            Uint256::from(u64::MAX).try_into().unwrap(),
            6,
        ),
    ];

    let (mut deps, TestMessage { router_message, .. }) =
        utils::setup_multiple_chains(configs.clone());
    let token_id = TokenId::new([1; 32]);
    let deploy_token = DeployInterchainToken {
        token_id,
        name: "Test".try_into().unwrap(),
        symbol: "TST".try_into().unwrap(),
        decimals: 18,
        minter: None,
    };
    let hub_message = HubMessage::SendToHub {
        destination_chain: configs[1].0.clone(),
        message: deploy_token.clone().into(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId {
            source_chain: configs[0].0.clone(),
            message_id: router_message.cc_id.message_id.clone()
        },
        source_its_contract.clone(),
        hub_message,
    ));

    let hub_message = HubMessage::SendToHub {
        destination_chain: configs[2].0.clone(),
        message: deploy_token.clone().into(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId {
            source_chain: configs[0].0.clone(),
            message_id: router_message.cc_id.message_id.clone()
        },
        source_its_contract.clone(),
        hub_message,
    ));

    let amount: nonempty::Uint256 = Uint256::from_u128(1000000000010000001u128)
        .try_into()
        .unwrap();

    // send from chain 0 to chain 1
    let transfer = InterchainTransfer {
        token_id,
        source_address: HexBinary::from([1; 32]).try_into().unwrap(),
        destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
        amount,
        data: None,
    };
    let hub_message = HubMessage::SendToHub {
        destination_chain: configs[1].0.clone(),
        message: transfer.into(),
    };

    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId {
            source_chain: configs[0].0.clone(),
            message_id: router_message.cc_id.message_id.clone()
        },
        source_its_contract.clone(),
        hub_message,
    ));

    let scaling_factor = Uint256::from_u128(10)
        .checked_pow(deploy_token.decimals.abs_diff(configs[1].3).into())
        .unwrap();
    let scaled_amount = amount.clone().checked_div(scaling_factor).unwrap();

    // send back from destination to source
    let transfer = InterchainTransfer {
        token_id,
        source_address: HexBinary::from([2; 32]).try_into().unwrap(),
        destination_address: HexBinary::from([1; 32]).try_into().unwrap(),
        amount: scaled_amount.try_into().unwrap(),
        data: None,
    };

    let hub_message = HubMessage::SendToHub {
        destination_chain: configs[2].0.clone(),
        message: transfer.into(),
    };

    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId {
            source_chain: configs[1].0.clone(),
            message_id: router_message.cc_id.message_id.clone()
        },
        source_its_contract.clone(),
        hub_message,
    ));

    let scaling_factor = Uint256::from_u128(10)
        .checked_pow(deploy_token.decimals.abs_diff(configs[2].3).into())
        .unwrap();
    let scaled_amount = amount.clone().checked_div(scaling_factor).unwrap();

    // send back from destination to source
    let transfer = InterchainTransfer {
        token_id,
        source_address: HexBinary::from([2; 32]).try_into().unwrap(),
        destination_address: HexBinary::from([1; 32]).try_into().unwrap(),
        amount: scaled_amount.try_into().unwrap(),
        data: None,
    };

    let hub_message = HubMessage::SendToHub {
        destination_chain: configs[0].0.clone(),
        message: transfer.into(),
    };

    let response_to_destination = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId {
            source_chain: configs[2].0.clone(),
            message_id: router_message.cc_id.message_id.clone()
        },
        source_its_contract,
        hub_message,
    ));

    goldie::assert_json!(response_to_destination);
}

#[test]
fn execute_message_deploy_interchain_token_should_translate_decimals_when_max_uints_are_different()
{
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_contract,
            source_its_chain,
            destination_its_chain,
            ..
        },
    ) = utils::setup_with_chain_configs(
        Uint256::MAX.try_into().unwrap(),
        6,
        u64::MAX.try_into().unwrap(),
        6,
    );

    let token_id = TokenId::new([1; 32]);
    let message = DeployInterchainToken {
        token_id,
        name: "Test".try_into().unwrap(),
        symbol: "TST".try_into().unwrap(),
        decimals: 18,
        minter: None,
    }
    .into();
    let hub_message = HubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message,
    };
    let response = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        hub_message,
    ));
    let source_token_instance = assert_ok!(utils::query_token_instance(
        deps.as_ref(),
        source_its_chain.clone(),
        token_id
    ));
    let destination_token_instance = assert_ok!(utils::query_token_instance(
        deps.as_ref(),
        destination_its_chain.clone(),
        token_id
    ));

    goldie::assert_json!(
        json!({ "response": response, "source_token_instance": source_token_instance, "destination_token_instance": destination_token_instance })
    );
}

#[test]
fn execute_message_deploy_interchain_token_should_translate_decimals_when_max_uints_are_the_same() {
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_chain,
            source_its_contract,
            destination_its_chain,
            ..
        },
    ) = utils::setup_with_chain_configs(
        Uint256::MAX.try_into().unwrap(),
        6,
        Uint256::MAX.try_into().unwrap(),
        6,
    );

    let token_id = TokenId::new([1; 32]);
    let message = DeployInterchainToken {
        token_id,
        name: "Test".try_into().unwrap(),
        symbol: "TST".try_into().unwrap(),
        decimals: 18,
        minter: None,
    }
    .into();
    let hub_message = HubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message,
    };
    let response = assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        hub_message,
    ));
    let source_token_instance = assert_ok!(utils::query_token_instance(
        deps.as_ref(),
        source_its_chain.clone(),
        token_id
    ));
    let destination_token_instance = assert_ok!(utils::query_token_instance(
        deps.as_ref(),
        destination_its_chain.clone(),
        token_id
    ));

    goldie::assert_json!(
        json!({ "response": response, "source_token_instance": source_token_instance, "destination_token_instance": destination_token_instance })
    );
}

#[test]
fn execute_its_when_not_gateway_sender_fails() {
    let mut deps = mock_dependencies();
    let api = deps.api;

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let result = contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make("not-gateway"), &[]),
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
        source_its_contract,
        ..
    } = TestMessage::dummy();

    utils::register_chain(
        deps.as_mut(),
        source_its_chain,
        source_its_contract,
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();

    let unknown_address: Address = "unknown-address".parse().unwrap();
    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id.clone(),
        unknown_address,
        hub_message.abi_encode(),
    );
    assert_err_contains!(
        result,
        ExecuteError,
        ExecuteError::UnknownItsContract { .. }
    );
}

#[test]
fn execute_message_when_invalid_payload_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        router_message,
        source_its_chain,
        source_its_contract,
        ..
    } = TestMessage::dummy();

    utils::register_chain(
        deps.as_mut(),
        source_its_chain,
        source_its_contract.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();

    let invalid_payload = HexBinary::from_hex("1234").unwrap();
    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract,
        invalid_payload,
    );
    assert_err_contains!(result, ExecuteError, ExecuteError::InvalidPayload);
}

#[test]
fn execute_message_when_unknown_chain_fails() {
    let mut deps = make_deps();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        hub_message,
        router_message,
        source_its_chain,
        source_its_contract,
        ..
    } = TestMessage::dummy();

    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        hub_message.clone().abi_encode(),
    );
    assert_err_contains!(result, ExecuteError, ExecuteError::State);

    utils::register_chain(
        deps.as_mut(),
        source_its_chain,
        source_its_contract.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();

    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id,
        source_its_contract,
        hub_message.abi_encode(),
    );
    assert_err_contains!(result, ExecuteError, ExecuteError::State);
}

#[test]
fn execute_message_when_invalid_message_type_fails() {
    let mut deps = make_deps();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        hub_message,
        router_message,
        source_its_chain,
        source_its_contract,
        ..
    } = TestMessage::dummy();

    utils::register_chain(
        deps.as_mut(),
        source_its_chain.clone(),
        source_its_contract.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    )
    .unwrap();

    let invalid_hub_message = HubMessage::ReceiveFromHub {
        source_chain: source_its_chain,
        message: hub_message.message().clone(),
    };
    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id,
        source_its_contract,
        invalid_hub_message.abi_encode(),
    );
    assert_err_contains!(result, ExecuteError, ExecuteError::InvalidMessageType);
}

#[test]
fn freeze_chain_when_not_admin_fails() {
    let mut deps = mock_dependencies();
    let api = deps.api;

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let result = contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make("not-admin"), &[]),
        ExecuteMsg::FreezeChain {
            chain: ChainNameRaw::try_from("ethereum").unwrap(),
        },
    );
    assert_err_contains!(
        result,
        permission_control::Error,
        permission_control::Error::PermissionDenied { .. }
    );
}

#[test]
fn unfreeze_chain_when_not_admin_fails() {
    let mut deps = mock_dependencies();
    let api = deps.api;

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let result = contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make("not-admin"), &[]),
        ExecuteMsg::UnfreezeChain {
            chain: ChainNameRaw::try_from("ethereum").unwrap(),
        },
    );
    assert_err_contains!(
        result,
        permission_control::Error,
        permission_control::Error::PermissionDenied { .. }
    );
}

#[test]
fn admin_or_governance_can_freeze_chain() {
    let mut deps = mock_dependencies();
    let api = deps.api;

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain = "ethereum".parse().unwrap();
    let max_uint = Uint256::from_str("120000000000000000000000000")
        .unwrap()
        .try_into()
        .unwrap();
    let decimals = 18;

    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    assert_ok!(utils::register_chain(
        deps.as_mut(),
        chain,
        address,
        max_uint,
        decimals
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make(params::ADMIN), &[]),
        ExecuteMsg::FreezeChain {
            chain: ChainNameRaw::try_from("ethereum").unwrap()
        }
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make(params::GOVERNANCE), &[]),
        ExecuteMsg::FreezeChain {
            chain: ChainNameRaw::try_from("ethereum").unwrap()
        }
    ));
}

#[test]
fn admin_or_governance_can_unfreeze_chain() {
    let mut deps = mock_dependencies();
    let api = deps.api;

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain = "ethereum".parse().unwrap();
    let max_uint = Uint256::from_str("120000000000000000000000000")
        .unwrap()
        .try_into()
        .unwrap();
    let decimals = 18;

    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    assert_ok!(utils::register_chain(
        deps.as_mut(),
        chain,
        address,
        max_uint,
        decimals
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make(params::ADMIN), &[]),
        ExecuteMsg::UnfreezeChain {
            chain: ChainNameRaw::try_from("ethereum").unwrap()
        }
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make(params::GOVERNANCE), &[]),
        ExecuteMsg::UnfreezeChain {
            chain: ChainNameRaw::try_from("ethereum").unwrap()
        }
    ));
}

#[test]
fn disable_execution_when_not_admin_fails() {
    let mut deps = mock_dependencies();
    let api = deps.api;

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let result = contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make("not-admin"), &[]),
        ExecuteMsg::DisableExecution,
    );
    assert_err_contains!(
        result,
        permission_control::Error,
        permission_control::Error::PermissionDenied { .. }
    );
}

#[test]
fn enable_execution_when_not_admin_fails() {
    let mut deps = mock_dependencies();
    let api = deps.api;

    utils::instantiate_contract(deps.as_mut()).unwrap();

    let result = contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make("not-admin"), &[]),
        ExecuteMsg::EnableExecution,
    );
    assert_err_contains!(
        result,
        permission_control::Error,
        permission_control::Error::PermissionDenied { .. }
    );
}

#[test]
fn admin_or_governance_can_enable_execution() {
    let mut deps = mock_dependencies();
    let api = deps.api;

    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make(params::ADMIN), &[]),
        ExecuteMsg::EnableExecution
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make(params::GOVERNANCE), &[]),
        ExecuteMsg::EnableExecution
    ));
}

#[test]
fn admin_or_governance_can_disable_execution() {
    let mut deps = mock_dependencies();
    let api = deps.api;

    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make(params::ADMIN), &[]),
        ExecuteMsg::DisableExecution
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        message_info(&api.addr_make(params::GOVERNANCE), &[]),
        ExecuteMsg::DisableExecution
    ));
}

#[test]
fn set_chain_config_should_succeed() {
    let chain = "ethereum".parse().unwrap();
    let max_uint = Uint256::from_str("120000000000000000000000000")
        .unwrap()
        .try_into()
        .unwrap();
    let decimals = 18;

    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_ok!(utils::register_chain(
        deps.as_mut(),
        chain,
        address,
        max_uint,
        decimals
    ));
}

#[test]
fn set_chain_config_should_fail_if_chain_config_is_already_set() {
    let chain: ChainNameRaw = "ethereum".parse().unwrap();
    let max_uint = Uint256::from_str("120000000000000000000000000")
        .unwrap()
        .try_into()
        .unwrap();
    let decimals = 18;

    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_ok!(utils::register_chain(
        deps.as_mut(),
        chain.clone(),
        address.clone(),
        max_uint,
        decimals
    ));
    assert_err_contains!(
        utils::register_chain(deps.as_mut(), chain, address, max_uint, decimals),
        ExecuteError,
        ExecuteError::ChainAlreadyRegistered(_)
    )
}

#[test]
fn deploy_interchain_token_tracks_supply() {
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_chain,
            source_its_contract,
            destination_its_chain,
            destination_its_contract,
            hub_message,
        },
    ) = utils::setup();

    let token_id = hub_message.token_id();
    let amount = nonempty::Uint256::try_from(400u64).unwrap();

    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        hub_message,
    ));

    let msg = HubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message: InterchainTransfer {
            token_id,
            source_address: HexBinary::from([1; 32]).try_into().unwrap(),
            destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
            amount,
            data: None,
        }
        .into(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        msg,
    ));

    assert_eq!(
        assert_ok!(utils::query_token_instance(
            deps.as_ref(),
            source_its_chain.clone(),
            token_id
        ))
        .unwrap()
        .supply,
        TokenSupply::Untracked,
    );
    assert_eq!(
        assert_ok!(utils::query_token_instance(
            deps.as_ref(),
            destination_its_chain.clone(),
            token_id
        ))
        .unwrap()
        .supply,
        TokenSupply::Tracked(amount.into())
    );

    // Send the same amount back
    let msg = HubMessage::SendToHub {
        destination_chain: source_its_chain.clone(),
        message: InterchainTransfer {
            token_id,
            source_address: HexBinary::from([1; 32]).try_into().unwrap(),
            destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
            amount,
            data: None,
        }
        .into(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId::new(
            destination_its_chain.clone(),
            router_message.cc_id.message_id.clone()
        )
        .unwrap(),
        destination_its_contract,
        msg,
    ));

    assert_eq!(
        assert_ok!(utils::query_token_instance(
            deps.as_ref(),
            source_its_chain.clone(),
            token_id
        ))
        .unwrap()
        .supply,
        TokenSupply::Untracked
    );
    assert_eq!(
        assert_ok!(utils::query_token_instance(
            deps.as_ref(),
            destination_its_chain,
            token_id
        ))
        .unwrap()
        .supply,
        TokenSupply::Tracked(Uint256::zero())
    );
}

#[test]
fn deploy_interchain_token_with_minter_does_not_track_supply() {
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_chain,
            source_its_contract,
            destination_its_chain,
            destination_its_contract,
            ..
        },
    ) = utils::setup();

    let token_id = TokenId::new([1u8; 32]);
    let amount = nonempty::Uint256::try_from(400u64).unwrap();

    let msg = HubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message: DeployInterchainToken {
            token_id,
            name: "Test".try_into().unwrap(),
            symbol: "TST".try_into().unwrap(),
            decimals: 18,
            minter: Some(HexBinary::from([1; 32]).try_into().unwrap()),
        }
        .into(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        msg,
    ));
    for chain in [source_its_chain.clone(), destination_its_chain.clone()] {
        assert_eq!(
            assert_ok!(utils::query_token_instance(
                deps.as_ref(),
                chain.clone(),
                token_id
            ))
            .unwrap()
            .supply,
            TokenSupply::Untracked,
        );
    }

    let msg = HubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message: InterchainTransfer {
            token_id,
            source_address: HexBinary::from([1; 32]).try_into().unwrap(),
            destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
            amount,
            data: None,
        }
        .into(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        msg,
    ));

    // Send a larger amount back
    let msg = HubMessage::SendToHub {
        destination_chain: source_its_chain.clone(),
        message: InterchainTransfer {
            token_id,
            source_address: HexBinary::from([1; 32]).try_into().unwrap(),
            destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
            amount: amount.strict_add(Uint256::one()).try_into().unwrap(),
            data: None,
        }
        .into(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        CrossChainId::new(
            destination_its_chain.clone(),
            router_message.cc_id.message_id.clone()
        )
        .unwrap(),
        destination_its_contract,
        msg,
    ));

    for chain in [source_its_chain.clone(), destination_its_chain.clone()] {
        assert_eq!(
            assert_ok!(utils::query_token_instance(
                deps.as_ref(),
                chain.clone(),
                token_id
            ))
            .unwrap()
            .supply,
            TokenSupply::Untracked,
        );
    }
}

#[test]
fn interchain_transfer_exceeds_supply_fails() {
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_chain,
            source_its_contract,
            destination_its_chain,
            destination_its_contract,
            hub_message: msg,
        },
    ) = utils::setup();

    let token_id = msg.token_id();
    let amount = nonempty::Uint256::try_from(400u64).unwrap();

    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        msg,
    ));

    let msg = HubMessage::SendToHub {
        destination_chain: source_its_chain.clone(),
        message: InterchainTransfer {
            token_id,
            source_address: HexBinary::from([1; 32]).try_into().unwrap(),
            destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
            amount: 1u64.try_into().unwrap(),
            data: None,
        }
        .into(),
    };
    assert_err_contains!(
        utils::execute_hub_message(
            deps.as_mut(),
            CrossChainId::new(
                destination_its_chain.clone(),
                router_message.cc_id.message_id.clone()
            )
            .unwrap(),
            destination_its_contract.clone(),
            msg,
        ),
        ExecuteError,
        ExecuteError::TokenSupplyInvariantViolated { .. }
    );

    let msg = HubMessage::SendToHub {
        destination_chain: destination_its_chain.clone(),
        message: InterchainTransfer {
            token_id,
            source_address: HexBinary::from([1; 32]).try_into().unwrap(),
            destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
            amount,
            data: None,
        }
        .into(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        msg,
    ));

    let msg = HubMessage::SendToHub {
        destination_chain: source_its_chain.clone(),
        message: InterchainTransfer {
            token_id,
            source_address: HexBinary::from([1; 32]).try_into().unwrap(),
            destination_address: HexBinary::from([2; 32]).try_into().unwrap(),
            amount: amount.strict_add(Uint256::one()).try_into().unwrap(),
            data: None,
        }
        .into(),
    };
    assert_err_contains!(
        utils::execute_hub_message(
            deps.as_mut(),
            CrossChainId::new(destination_its_chain, router_message.cc_id.message_id).unwrap(),
            destination_its_contract,
            msg,
        ),
        ExecuteError,
        ExecuteError::TokenSupplyInvariantViolated { .. }
    );
}

#[test]
fn deploy_interchain_token_submitted_twice_fails() {
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_contract,
            hub_message: msg,
            ..
        },
    ) = utils::setup();

    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        msg.clone(),
    ));

    assert_err_contains!(
        utils::execute_hub_message(
            deps.as_mut(),
            router_message.cc_id.clone(),
            source_its_contract.clone(),
            msg,
        ),
        ExecuteError,
        ExecuteError::TokenAlreadyDeployed { .. }
    );
}

#[test]
fn deploy_interchain_token_from_non_origin_chain_fails() {
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_contract,
            hub_message: msg,
            ..
        },
    ) = utils::setup();

    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        msg.clone(),
    ));

    // Deploy the same token from a different origin chain to a different destination chain now
    let another_source_chain: ChainNameRaw = "another-source-chain".parse().unwrap();
    assert_ok!(utils::register_chain(
        deps.as_mut(),
        another_source_chain.clone(),
        source_its_contract.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    ));
    let another_destination_chain: ChainNameRaw = "another-dest-chain".parse().unwrap();
    assert_ok!(utils::register_chain(
        deps.as_mut(),
        another_destination_chain.clone(),
        source_its_contract.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    ));

    let new_destination_msg = HubMessage::SendToHub {
        destination_chain: another_source_chain.clone(),
        message: msg.message().clone(),
    };

    assert_err_contains!(
        utils::execute_hub_message(
            deps.as_mut(),
            CrossChainId::new(another_source_chain, router_message.cc_id.message_id).unwrap(),
            source_its_contract,
            new_destination_msg,
        ),
        ExecuteError,
        ExecuteError::TokenDeployedFromNonOriginChain { .. }
    );
}

#[test]
fn deploy_interchain_token_to_multiple_destination_succeeds() {
    let (
        mut deps,
        TestMessage {
            router_message,
            source_its_contract,
            hub_message: msg,
            ..
        },
    ) = utils::setup();

    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        msg.clone(),
    ));

    let another_chain: ChainNameRaw = "another-chain".parse().unwrap();
    assert_ok!(utils::register_chain(
        deps.as_mut(),
        another_chain.clone(),
        source_its_contract.clone(),
        Uint256::MAX.try_into().unwrap(),
        u8::MAX,
    ));

    let msg = HubMessage::SendToHub {
        destination_chain: another_chain,
        message: msg.message().clone(),
    };
    assert_ok!(utils::execute_hub_message(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        msg.clone(),
    ));
}

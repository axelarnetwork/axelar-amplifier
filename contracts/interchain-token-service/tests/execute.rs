use std::str::FromStr;

use assert_ok::assert_ok;
use axelar_wasm_std::response::inspect_response_msg;
use axelar_wasm_std::{assert_err_contains, nonempty, permission_control};
use axelarnet_gateway::msg::ExecuteMsg as AxelarnetGatewayExecuteMsg;
use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use cosmwasm_std::{HexBinary, Uint256};
use interchain_token_service::contract::{self, ExecuteError};
use interchain_token_service::events::Event;
use interchain_token_service::msg::ExecuteMsg;
use interchain_token_service::{
    DeployInterchainToken, DeployTokenManager, HubMessage, InterchainTransfer, TokenId,
    TokenManagerType, TokenSupply,
};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};
use utils::{params, TestMessage};

mod utils;

#[test]
fn register_deregister_its_contract_succeeds() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainNameRaw = "ethereum".parse().unwrap();
    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    let register_response = assert_ok!(utils::register_its_contract(
        deps.as_mut(),
        chain.clone(),
        address.clone()
    ));
    let res = assert_ok!(utils::query_its_contract(deps.as_ref(), chain.clone()));
    assert_eq!(res, Some(address));

    let deregister_response =
        assert_ok!(utils::deregister_its_contract(deps.as_mut(), chain.clone()));
    let res = assert_ok!(utils::query_its_contract(deps.as_ref(), chain.clone()));
    assert_eq!(res, None);

    goldie::assert_json!([register_response, deregister_response]);
}

#[test]
fn reregistering_its_contract_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainNameRaw = "ethereum".parse().unwrap();
    let address: Address = "0x1234567890123456789012345678901234567890"
        .parse()
        .unwrap();

    assert_ok!(utils::register_its_contract(
        deps.as_mut(),
        chain.clone(),
        address.clone()
    ));

    assert_err_contains!(
        utils::register_its_contract(deps.as_mut(), chain, address),
        ExecuteError,
        ExecuteError::FailedItsContractRegistration(..)
    );
}

#[test]
fn deregistering_unknown_chain_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain: ChainNameRaw = "ethereum".parse().unwrap();

    assert_err_contains!(
        utils::deregister_its_contract(deps.as_mut(), chain),
        ExecuteError,
        ExecuteError::FailedItsContractDeregistration(..)
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
        DeployTokenManager {
            token_id: TokenId::new([2; 32]),
            token_manager_type: TokenManagerType::MintBurn,
            params: HexBinary::from([1, 2, 3, 4]).try_into().unwrap(),
        }
        .into(),
        InterchainTransfer {
            token_id: TokenId::new([2; 32]),
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
        source_its_contract,
        ..
    } = TestMessage::dummy();

    utils::register_its_contract(deps.as_mut(), source_its_chain, source_its_contract).unwrap();

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

    utils::register_its_contract(deps.as_mut(), source_its_chain, source_its_contract.clone())
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
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let TestMessage {
        hub_message,
        router_message,
        source_its_chain,
        source_its_contract,
        destination_its_chain,
        ..
    } = TestMessage::dummy();

    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id.clone(),
        source_its_contract.clone(),
        hub_message.clone().abi_encode(),
    );
    assert_err_contains!(result, ExecuteError, ExecuteError::UnknownChain(chain) if chain == &source_its_chain);

    utils::register_its_contract(deps.as_mut(), source_its_chain, source_its_contract.clone())
        .unwrap();

    let result = utils::execute(
        deps.as_mut(),
        router_message.cc_id,
        source_its_contract,
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
        source_its_contract,
        ..
    } = TestMessage::dummy();

    utils::register_its_contract(
        deps.as_mut(),
        source_its_chain.clone(),
        source_its_contract.clone(),
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
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let result = contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info("not-admin", &[]),
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
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let result = contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info("not-admin", &[]),
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
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain = "ethereum".parse().unwrap();
    let max_uint = Uint256::from_str("120000000000000000000000000")
        .unwrap()
        .try_into()
        .unwrap();
    let decimals = 18;

    assert_ok!(utils::set_chain_config(
        deps.as_mut(),
        chain,
        max_uint,
        decimals
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info(params::ADMIN, &[]),
        ExecuteMsg::FreezeChain {
            chain: ChainNameRaw::try_from("ethereum").unwrap()
        }
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info(params::GOVERNANCE, &[]),
        ExecuteMsg::FreezeChain {
            chain: ChainNameRaw::try_from("ethereum").unwrap()
        }
    ));
}

#[test]
fn admin_or_governance_can_unfreeze_chain() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let chain = "ethereum".parse().unwrap();
    let max_uint = Uint256::from_str("120000000000000000000000000")
        .unwrap()
        .try_into()
        .unwrap();
    let decimals = 18;

    assert_ok!(utils::set_chain_config(
        deps.as_mut(),
        chain,
        max_uint,
        decimals
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info(params::ADMIN, &[]),
        ExecuteMsg::UnfreezeChain {
            chain: ChainNameRaw::try_from("ethereum").unwrap()
        }
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info(params::GOVERNANCE, &[]),
        ExecuteMsg::UnfreezeChain {
            chain: ChainNameRaw::try_from("ethereum").unwrap()
        }
    ));
}

#[test]
fn disable_execution_when_not_admin_fails() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let result = contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info("not-admin", &[]),
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
    utils::instantiate_contract(deps.as_mut()).unwrap();

    let result = contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info("not-admin", &[]),
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
    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info(params::ADMIN, &[]),
        ExecuteMsg::EnableExecution
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info(params::GOVERNANCE, &[]),
        ExecuteMsg::EnableExecution
    ));
}

#[test]
fn admin_or_governance_can_disable_execution() {
    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info(params::ADMIN, &[]),
        ExecuteMsg::DisableExecution
    ));

    assert_ok!(contract::execute(
        deps.as_mut(),
        mock_env(),
        mock_info(params::GOVERNANCE, &[]),
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

    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_ok!(utils::set_chain_config(
        deps.as_mut(),
        chain,
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

    let mut deps = mock_dependencies();
    utils::instantiate_contract(deps.as_mut()).unwrap();

    assert_ok!(utils::set_chain_config(
        deps.as_mut(),
        chain.clone(),
        max_uint,
        decimals
    ));
    assert_err_contains!(
        utils::set_chain_config(deps.as_mut(), chain, max_uint, decimals),
        ExecuteError,
        ExecuteError::ChainConfigAlreadySet(_)
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
    utils::register_chain(
        &mut deps,
        another_source_chain.clone(),
        source_its_contract.clone(),
    );
    let another_destination_chain: ChainNameRaw = "another-dest-chain".parse().unwrap();
    utils::register_chain(
        &mut deps,
        another_destination_chain.clone(),
        source_its_contract.clone(),
    );

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
    utils::register_chain(
        &mut deps,
        another_chain.clone(),
        source_its_contract.clone(),
    );

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

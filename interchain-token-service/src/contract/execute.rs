use cosmwasm_std::{DepsMut, HexBinary, Response};
use error_stack::{report, Result, ResultExt};
use router_api::{Address, ChainName, CrossChainId};

use crate::contract::Error;
use crate::events::ItsContractEvent;
use crate::primitives::ItsHubMessage;
use crate::state::{self, load_config, load_trusted_address};

/// Executes an incoming ITS message.
///
/// This function handles the execution of ITS (Interchain Token Service) messages received from
/// trusted sources. It verifies the source address, decodes the message, applies balance tracking,
/// and forwards the message to the destination chain.
pub fn execute_message(
    deps: DepsMut,
    cc_id: CrossChainId,
    source_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let config = load_config(deps.storage).change_context(Error::InvalidStoreAccess)?;

    let source_chain = ChainName::try_from(cc_id.source_chain.clone().to_string())
        .change_context(Error::InvalidPayload)?;
    let trusted_source_address = load_trusted_address(deps.storage, &source_chain)
        .change_context(Error::InvalidStoreAccess)?;
    if source_address != trusted_source_address {
        return Err(report!(Error::UntrustedAddress(source_address)));
    }

    let its_hub_message =
        ItsHubMessage::abi_decode(&payload).change_context(Error::InvalidPayload)?;

    match its_hub_message {
        ItsHubMessage::SendToHub {
            destination_chain,
            message: its_message,
        } => {
            let receive_from_hub = ItsHubMessage::ReceiveFromHub {
                source_chain: source_chain.clone(),
                message: its_message.clone(),
            };
            let encoded_payload = receive_from_hub.abi_encode();

            let destination_address = load_trusted_address(deps.storage, &destination_chain)
                .change_context(Error::InvalidStoreAccess)?;

            let gateway: axelarnet_gateway::Client =
                client::Client::new(deps.querier, config.gateway).into();

            let call_contract_msg = gateway.call_contract(
                destination_chain.clone(),
                destination_address,
                encoded_payload,
            );

            Ok(Response::new().add_message(call_contract_msg).add_event(
                ItsContractEvent::ItsMessageReceived {
                    source_chain,
                    destination_chain,
                    message: its_message,
                }
                .into(),
            ))
        }
        _ => Err(report!(Error::InvalidPayload)),
    }
}

pub fn set_trusted_address(
    deps: DepsMut,
    chain: ChainName,
    address: Address,
) -> Result<Response, Error> {
    state::save_trusted_address(deps.storage, &chain, &address)
        .change_context(Error::InvalidStoreAccess)?;

    Ok(Response::new().add_event(ItsContractEvent::TrustedAddressSet { chain, address }.into()))
}

pub fn remove_trusted_address(deps: DepsMut, chain: ChainName) -> Result<Response, Error> {
    state::remove_trusted_address(deps.storage, &chain);

    Ok(Response::new().add_event(ItsContractEvent::TrustedAddressRemoved { chain }.into()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axelar_wasm_std::err_contains;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{Addr, CosmosMsg, DepsMut, Empty, Event, OwnedDeps, Uint256};
    use router_api::{Address, ChainName, CrossChainId};

    use super::*;
    use crate::contract::instantiate;
    use crate::events::ItsContractEvent;
    use crate::msg::InstantiateMsg;
    use crate::primitives::{ItsHubMessage, ItsMessage, TokenId};
    use crate::state::{self, save_trusted_address};

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("creator", &[]);

        // Initialize the contract
        let msg = InstantiateMsg {
            governance_address: "governance".to_string(),
            admin_address: "admin".to_string(),
            chain_name: "source-chain".parse().unwrap(),
            gateway_address: "gateway".to_string(),
            trusted_addresses: HashMap::new(),
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        deps
    }

    fn register_trusted_address(deps: &mut DepsMut, chain: &str, address: &str) {
        let chain: ChainName = chain.parse().unwrap();
        let address: Address = address.parse().unwrap();
        save_trusted_address(deps.storage, &chain, &address).unwrap();
    }

    fn generate_its_message() -> ItsMessage {
        ItsMessage::InterchainTransfer {
            token_id: TokenId::new([0u8; 32]),
            source_address: HexBinary::from_hex("1234").unwrap(),
            destination_address: HexBinary::from_hex("5678").unwrap(),
            amount: Uint256::from(1000u128),
            data: HexBinary::from_hex("abcd").unwrap(),
        }
    }

    #[test]
    fn execute_message_send_to_hub() {
        let mut deps = setup();

        let source_chain: ChainName = "source-chain".parse().unwrap();
        let destination_chain: ChainName = "destination-chain".parse().unwrap();
        let source_address: Address = "trusted-source".parse().unwrap();
        let destination_address: Address = "trusted-destination".parse().unwrap();

        register_trusted_address(&mut deps.as_mut(), source_chain.as_ref(), &source_address);
        register_trusted_address(
            &mut deps.as_mut(),
            destination_chain.as_ref(),
            &destination_address,
        );

        let its_message = generate_its_message();
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: its_message.clone(),
        };

        let payload = its_hub_message.abi_encode();
        let cc_id = CrossChainId::new(source_chain.clone(), "message-id").unwrap();
        let result = execute_message(deps.as_mut(), cc_id, source_address, payload).unwrap();

        let axelarnet_gateway: axelarnet_gateway::Client =
            client::Client::new(deps.as_mut().querier, Addr::unchecked("gateway")).into();
        let expected_msg = axelarnet_gateway.call_contract(
            destination_chain.clone(),
            destination_address,
            ItsHubMessage::ReceiveFromHub {
                source_chain: source_chain.clone(),
                message: its_message.clone(),
            }
            .abi_encode(),
        );
        assert_eq!(result.messages.len(), 1);
        assert_eq!(result.messages[0].msg, CosmosMsg::Wasm(expected_msg));

        let expected_event = ItsContractEvent::ItsMessageReceived {
            source_chain,
            destination_chain,
            message: its_message,
        };
        assert_eq!(result.events, vec![Event::from(expected_event)]);
    }

    #[test]
    fn execute_message_untrusted_address() {
        let mut owned_deps = setup();
        let mut deps = owned_deps.as_mut();

        register_trusted_address(&mut deps, "source-chain", "trusted-source");

        let its_message = generate_its_message();
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: "destination-chain".parse().unwrap(),
            message: its_message,
        };

        let payload = its_hub_message.abi_encode();
        let cc_id = CrossChainId::new("source-chain", "message-id").unwrap();
        let source_address: Address = "untrusted-source".parse().unwrap();
        let result = execute_message(deps, cc_id, source_address.clone(), payload).unwrap_err();

        assert!(err_contains!(result, Error, Error::UntrustedAddress(..)));
    }

    #[test]
    fn execute_message_invalid_payload() {
        let mut owned_deps = setup();
        let mut deps = owned_deps.as_mut();

        register_trusted_address(&mut deps, "source-chain", "trusted-source");

        let invalid_payload = HexBinary::from_hex("deaddead").unwrap();
        let cc_id = CrossChainId::new("source-chain", "message-id").unwrap();
        let source_address: Address = "trusted-source".parse().unwrap();
        let result = execute_message(deps, cc_id, source_address, invalid_payload).unwrap_err();

        assert!(err_contains!(result, Error, Error::InvalidPayload));
    }

    #[test]
    fn check_updated_trusted_address() {
        let mut deps = setup();

        let chain: ChainName = "new-chain".parse().unwrap();
        let address: Address = "new-trusted-address".parse().unwrap();

        let result = set_trusted_address(deps.as_mut(), chain.clone(), address.clone()).unwrap();

        assert_eq!(result.messages.len(), 0);

        let event = &result.events[0];
        let expected_event = ItsContractEvent::TrustedAddressSet {
            chain: chain.clone(),
            address: address.clone(),
        };
        assert_eq!(event, &cosmwasm_std::Event::from(expected_event));

        let saved_address = load_trusted_address(deps.as_mut().storage, &chain).unwrap();
        assert_eq!(saved_address, address);
    }

    #[test]
    fn execute_message_unknown_destination() {
        let mut owned_deps = setup();
        let mut deps = owned_deps.as_mut();

        register_trusted_address(&mut deps, "source-chain", "trusted-source");

        let its_message = generate_its_message();
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: "unknown-chain".parse().unwrap(),
            message: its_message,
        };

        let payload = its_hub_message.abi_encode();
        let cc_id = CrossChainId::new("source-chain", "message-id").unwrap();
        let source_address: Address = "trusted-source".parse().unwrap();
        let result = execute_message(deps, cc_id, source_address, payload).unwrap_err();

        assert!(err_contains!(
            result,
            state::Error,
            state::Error::TrustedAddressNotFound(..)
        ));
    }

    #[test]
    fn execute_message_receive_from_hub() {
        let mut owned_deps = setup();
        let mut deps = owned_deps.as_mut();

        register_trusted_address(&mut deps, "source-chain", "trusted-source");

        let its_message = generate_its_message();
        let its_hub_message = ItsHubMessage::ReceiveFromHub {
            source_chain: "source-chain".parse().unwrap(),
            message: its_message.clone(),
        };

        let payload = its_hub_message.abi_encode();
        let cc_id = CrossChainId::new("source-chain", "message-id").unwrap();
        let source_address: Address = "trusted-source".parse().unwrap();
        let result = execute_message(deps, cc_id, source_address, payload).unwrap_err();

        assert!(err_contains!(result, Error, Error::InvalidPayload));
    }
}

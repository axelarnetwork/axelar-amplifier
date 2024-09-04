use axelar_wasm_std::IntoContractError;
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::primitives::ItsHubMessage;
use crate::state::{self, load_config, load_its_address};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("unknown chain {0}")]
    UnknownChain(ChainName),
    #[error("unknown its address {0}")]
    UnknownItsAddress(Address),
    #[error("failed to decode payload")]
    InvalidPayload,
    #[error("invalid message type")]
    InvalidMessageType,
}

/// Executes an incoming ITS message.
///
/// This function handles the execution of ITS (Interchain Token Service) messages received from
/// its sources. It verifies the source address, decodes the message, applies balance tracking,
/// and forwards the message to the destination chain.
pub fn execute_message(
    deps: DepsMut,
    cc_id: CrossChainId,
    source_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    ensure_its_source_address(deps.storage, &cc_id.source_chain, &source_address)?;

    match ItsHubMessage::abi_decode(&payload).change_context(Error::InvalidPayload)? {
        ItsHubMessage::SendToHub {
            destination_chain,
            message,
        } => {
            let destination_address = load_its_address(deps.storage, &destination_chain)
                .change_context_lazy(|| Error::UnknownChain(destination_chain.clone()))?;

            let destination_payload = ItsHubMessage::ReceiveFromHub {
                source_chain: cc_id.source_chain.clone(),
                message: message.clone(),
            }
            .abi_encode();

            Ok(send_to_destination(
                deps.storage,
                deps.querier,
                destination_chain.clone(),
                destination_address,
                destination_payload,
            )?
            .add_event(
                Event::ItsMessageReceived {
                    cc_id,
                    destination_chain,
                    message,
                }
                .into(),
            ))
        }
        _ => bail!(Error::InvalidMessageType),
    }
}

fn to_chain_name(chain: &ChainNameRaw) -> ChainName {
    ChainName::try_from(chain.as_ref()).expect("invalid chain name")
}

fn ensure_its_source_address(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    source_address: &Address,
) -> Result<(), Error> {
    let source_chain = to_chain_name(source_chain);
    let its_source_address = load_its_address(storage, &source_chain)
        .change_context_lazy(|| Error::UnknownChain(source_chain.clone()))?;

    ensure!(
        source_address == &its_source_address,
        Error::UnknownItsAddress(source_address.clone())
    );

    Ok(())
}

fn send_to_destination(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: ChainName,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let config = load_config(storage);

    let gateway: axelarnet_gateway::Client =
        client::Client::new(querier, &config.axelarnet_gateway).into();

    let call_contract_msg = gateway.call_contract(destination_chain, destination_address, payload);

    Ok(Response::new().add_message(call_contract_msg))
}

pub fn register_its_address(
    deps: DepsMut,
    chain: ChainName,
    address: Address,
) -> Result<Response, Error> {
    state::save_its_address(deps.storage, &chain, &address)
        .change_context_lazy(|| Error::UnknownChain(chain.clone()))?;

    Ok(Response::new().add_event(Event::ItsAddressRegistered { chain, address }.into()))
}

pub fn deregister_its_address(deps: DepsMut, chain: ChainName) -> Result<Response, Error> {
    state::remove_its_address(deps.storage, &chain);

    Ok(Response::new().add_event(Event::ItsAddressDeregistered { chain }.into()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_ok::assert_ok;
    use axelar_wasm_std::err_contains;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
    };
    use cosmwasm_std::{Empty, OwnedDeps, Uint256};
    use router_api::{Address, ChainName, CrossChainId};

    use super::*;
    use crate::contract::instantiate;
    use crate::events::Event;
    use crate::msg::InstantiateMsg;
    use crate::primitives::{ItsHubMessage, ItsMessage, TokenId};
    use crate::state;

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("creator", &[]);

        // Initialize the contract
        let msg = InstantiateMsg {
            governance_address: "governance".to_string(),
            admin_address: "admin".to_string(),
            axelarnet_gateway_address: "gateway".to_string(),
            its_addresses: HashMap::new(),
        };

        assert_ok!(instantiate(deps.as_mut(), env.clone(), info.clone(), msg));

        deps
    }

    fn dummy_its_message() -> ItsMessage {
        ItsMessage::InterchainTransfer {
            token_id: TokenId::new([0u8; 32]),
            source_address: HexBinary::from_hex("1234").unwrap(),
            destination_address: HexBinary::from_hex("5678").unwrap(),
            amount: Uint256::from(1000u128),
            data: HexBinary::from_hex("abcd").unwrap(),
        }
    }

    #[test]
    fn execute_message_when_unknown_source_address_fails() {
        let mut deps = setup();
        let source_chain: ChainName = "source-chain".parse().unwrap();
        let source_address: Address = "its-source".parse().unwrap();
        let cc_id = CrossChainId::new(source_chain.clone(), "message-id").unwrap();

        register_its_address(deps.as_mut(), source_chain.clone(), source_address).unwrap();

        let its_message = dummy_its_message();
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: "destination-chain".parse().unwrap(),
            message: its_message,
        };

        let payload = its_hub_message.abi_encode();
        let invalid_address: Address = "invalid-address".parse().unwrap();

        let result = execute_message(deps.as_mut(), cc_id, invalid_address, payload).unwrap_err();
        assert!(err_contains!(result, Error, Error::UnknownItsAddress(..)));
    }

    #[test]
    fn execute_message_when_invalid_payload_fails() {
        let mut deps = setup();
        let source_chain: ChainName = "source-chain".parse().unwrap();
        let source_address: Address = "its-source".parse().unwrap();
        let cc_id = CrossChainId::new(source_chain.clone(), "message-id").unwrap();

        register_its_address(deps.as_mut(), source_chain.clone(), source_address.clone()).unwrap();

        let invalid_payload = HexBinary::from_hex("deaddead").unwrap();
        let result =
            execute_message(deps.as_mut(), cc_id, source_address, invalid_payload).unwrap_err();
        assert!(err_contains!(result, Error, Error::InvalidPayload));
    }

    #[test]
    fn register_its_address_succeeds() {
        let mut deps = setup();

        let chain: ChainName = "new-chain".parse().unwrap();
        let address: Address = "new-its-address".parse().unwrap();

        let result = register_its_address(deps.as_mut(), chain.clone(), address.clone()).unwrap();

        assert_eq!(result.messages.len(), 0);

        let event = &result.events[0];
        let expected_event = Event::ItsAddressRegistered {
            chain: chain.clone(),
            address: address.clone(),
        };
        assert_eq!(event, &cosmwasm_std::Event::from(expected_event));

        let saved_address = load_its_address(deps.as_mut().storage, &chain).unwrap();
        assert_eq!(saved_address, address);
    }

    #[test]
    fn execute_message_when_unknown_destination_fails() {
        let mut deps = setup();
        let source_chain: ChainName = "source-chain".parse().unwrap();
        let source_address: Address = "its-source".parse().unwrap();
        let cc_id = CrossChainId::new(source_chain.clone(), "message-id").unwrap();

        register_its_address(deps.as_mut(), source_chain.clone(), source_address.clone()).unwrap();

        let its_message = dummy_its_message();
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: "unknown-chain".parse().unwrap(),
            message: its_message,
        };

        let payload = its_hub_message.abi_encode();
        let result = execute_message(deps.as_mut(), cc_id, source_address, payload).unwrap_err();
        assert!(err_contains!(
            result,
            state::Error,
            state::Error::ItsAddressNotFound(..)
        ));
    }

    #[test]
    fn execute_message_when_invalid_message_type_fails() {
        let mut deps = setup();
        let source_chain: ChainName = "source-chain".parse().unwrap();
        let source_address: Address = "its-source".parse().unwrap();
        let cc_id = CrossChainId::new(source_chain.clone(), "message-id").unwrap();

        register_its_address(deps.as_mut(), source_chain.clone(), source_address.clone()).unwrap();

        let its_message = dummy_its_message();
        let its_hub_message = ItsHubMessage::ReceiveFromHub {
            source_chain: source_chain.clone().into(),
            message: its_message.clone(),
        };

        let payload = its_hub_message.abi_encode();
        let result = execute_message(deps.as_mut(), cc_id, source_address, payload).unwrap_err();
        assert!(err_contains!(result, Error, Error::InvalidMessageType));
    }
}

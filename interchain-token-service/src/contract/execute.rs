use cosmwasm_std::{DepsMut, HexBinary, Response, Storage};
use error_stack::{report, Result, ResultExt};
use router_api::{Address, ChainName, CrossChainId};

use crate::contract::Error;
use crate::events::ItsContractEvent;
use crate::primitives::ItsHubMessage;
use crate::state::{
    load_config, load_trusted_address, save_trusted_address, start_token_balance,
    update_token_balance,
};
use crate::ItsMessage;

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
            apply_balance_tracking(
                deps.storage,
                source_chain.clone(),
                destination_chain.clone(),
                &its_message,
            )?;

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

/// Applies balance tracking logic for interchain transfers and token deployments.
///
/// This function handles different types of ITS messages and applies the appropriate
/// balance changes or initializations based on the message type.
///
/// # Behavior for different ITS message types
///
/// 1. InterchainTransfer:
///    - Decreases the token balance on the source chain.
///    - Increases the token balance on the destination chain.
///    - If the balance becomes insufficient on the source chain, an error is returned.
///
/// 2. DeployInterchainToken:
///    - Initializes balance tracking for the token on the destination chain.
///    - Sets the initial balance to zero.
///    - The source chain is not checked, as the token might originate from there.
///
/// 3. DeployTokenManager:
///    - Initializes the token on the destination chain, but doesn't track balances. This prevents the token from being deployed to the same chain again.
///    - The source chain is not checked, as the token might originate from there, or not follow standard lock-and-mint mechanism.
fn apply_balance_tracking(
    storage: &mut dyn Storage,
    source_chain: ChainName,
    destination_chain: ChainName,
    message: &ItsMessage,
) -> Result<(), Error> {
    match message {
        ItsMessage::InterchainTransfer {
            token_id, amount, ..
        } => {
            // Update the balance on the source chain
            update_token_balance(
                storage,
                token_id.clone(),
                source_chain.clone(),
                *amount,
                false,
            )
            .change_context_lazy(|| Error::BalanceUpdateFailed(source_chain, token_id.clone()))?;

            // Update the balance on the destination chain
            update_token_balance(
                storage,
                token_id.clone(),
                destination_chain.clone(),
                *amount,
                true,
            )
            .change_context_lazy(|| {
                Error::BalanceUpdateFailed(destination_chain, token_id.clone())
            })?
        }
        // Start balance tracking for the token on the destination chain when a token deployment is seen
        // No invariants can be assumed on the source since the token might pre-exist on the source chain
        ItsMessage::DeployInterchainToken { token_id, .. } => {
            start_token_balance(storage, token_id.clone(), destination_chain.clone(), true)
                .change_context(Error::InvalidStoreAccess)?
        }
        ItsMessage::DeployTokenManager { token_id, .. } => {
            start_token_balance(storage, token_id.clone(), destination_chain.clone(), false)
                .change_context(Error::InvalidStoreAccess)?
        }
    };

    Ok(())
}

pub fn update_trusted_address(
    deps: DepsMut,
    chain: ChainName,
    address: Address,
) -> Result<Response, Error> {
    save_trusted_address(deps.storage, &chain, &address)
        .change_context(Error::InvalidStoreAccess)?;

    Ok(
        Response::new()
            .add_event(ItsContractEvent::TrustedAddressUpdated { chain, address }.into()),
    )
}

#[cfg(test)]
mod tests {
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
    use crate::state::{self, save_trusted_address, TokenBalance};

    fn setup() -> OwnedDeps<MockStorage, MockApi, MockQuerier, Empty> {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("creator", &[]);

        // Initialize the contract
        let msg = InstantiateMsg {
            chain_name: "source-chain".parse().unwrap(),
            gateway_address: "gateway".to_string(),
            trusted_addresses: None,
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
    fn test_execute_message_send_to_hub() {
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

        let result = update_trusted_address(deps.as_mut(), chain.clone(), address.clone()).unwrap();

        assert_eq!(result.messages.len(), 0);

        let event = &result.events[0];
        let expected_event = ItsContractEvent::TrustedAddressUpdated {
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

    #[test]
    fn balance_tracking_interchain_transfer() {
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

        let token_id = TokenId::new([1u8; 32]);
        let amount = Uint256::from(1000u128);

        // Initialize balance tracking for the token on both chains
        state::start_token_balance(
            deps.as_mut().storage,
            token_id.clone(),
            source_chain.clone(),
            true,
        )
        .unwrap();
        state::start_token_balance(
            deps.as_mut().storage,
            token_id.clone(),
            destination_chain.clone(),
            true,
        )
        .unwrap();

        // Simulate an initial balance on the source chain
        state::update_token_balance(
            deps.as_mut().storage,
            token_id.clone(),
            source_chain.clone(),
            amount,
            true,
        )
        .unwrap();

        let transfer_message = ItsMessage::InterchainTransfer {
            token_id: token_id.clone(),
            source_address: HexBinary::from_hex("1234").unwrap(),
            destination_address: HexBinary::from_hex("5678").unwrap(),
            amount,
            data: HexBinary::from_hex("abcd").unwrap(),
        };
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: transfer_message,
        };

        let payload = its_hub_message.abi_encode();
        let cc_id = CrossChainId::new(source_chain.clone(), "transfer-message-id").unwrap();
        execute_message(deps.as_mut(), cc_id, source_address, payload).unwrap();

        // Check balances after transfer
        let source_balance =
            state::may_load_token_balance(deps.as_ref().storage, &token_id, &source_chain).unwrap();
        let destination_balance =
            state::may_load_token_balance(deps.as_ref().storage, &token_id, &destination_chain)
                .unwrap();

        assert_eq!(source_balance, Some(TokenBalance::Tracked(Uint256::zero())));
        assert_eq!(destination_balance, Some(TokenBalance::Tracked(amount)));
    }

    #[test]
    fn balance_tracking_deploy_interchain_token() {
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

        let token_id = TokenId::new([2u8; 32]);

        let deploy_message = ItsMessage::DeployInterchainToken {
            token_id: token_id.clone(),
            name: "Test Token".to_string(),
            symbol: "TST".to_string(),
            decimals: 18,
            minter: HexBinary::from_hex("1234").unwrap(),
        };
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: deploy_message,
        };

        let payload = its_hub_message.abi_encode();
        let cc_id = CrossChainId::new(source_chain.clone(), "deploy-message-id").unwrap();
        execute_message(deps.as_mut(), cc_id, source_address, payload).unwrap();

        // Check if balance tracking is initialized on the destination chain
        let destination_balance =
            state::may_load_token_balance(deps.as_ref().storage, &token_id, &destination_chain)
                .unwrap();
        assert_eq!(
            destination_balance,
            Some(TokenBalance::Tracked(Uint256::zero()))
        );

        // Check that balance tracking is not initialized on the source chain
        let source_balance =
            state::may_load_token_balance(deps.as_ref().storage, &token_id, &source_chain).unwrap();
        assert_eq!(source_balance, None);
    }

    #[test]
    fn balance_tracking_insufficient_balance() {
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

        let token_id = TokenId::new([3u8; 32]);
        let initial_amount = Uint256::from(500u128);
        let transfer_amount = Uint256::from(1000u128);

        // Initialize balance tracking and set initial balance
        state::start_token_balance(
            deps.as_mut().storage,
            token_id.clone(),
            source_chain.clone(),
            true,
        )
        .unwrap();
        state::update_token_balance(
            deps.as_mut().storage,
            token_id.clone(),
            source_chain.clone(),
            initial_amount,
            true,
        )
        .unwrap();

        let transfer_message = ItsMessage::InterchainTransfer {
            token_id: token_id.clone(),
            source_address: HexBinary::from_hex("1234").unwrap(),
            destination_address: HexBinary::from_hex("5678").unwrap(),
            amount: transfer_amount,
            data: HexBinary::from_hex("abcd").unwrap(),
        };
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: transfer_message,
        };

        let payload = its_hub_message.abi_encode();
        let cc_id =
            CrossChainId::new(source_chain.clone(), "insufficient-balance-message-id").unwrap();
        let result = execute_message(deps.as_mut(), cc_id, source_address, payload);

        assert!(result.is_err());
        assert!(err_contains!(
            result.unwrap_err(),
            Error,
            Error::BalanceUpdateFailed(..)
        ));

        // Check that the balances remain unchanged
        let source_balance =
            state::may_load_token_balance(deps.as_ref().storage, &token_id, &source_chain).unwrap();
        assert_eq!(source_balance, Some(TokenBalance::Tracked(initial_amount)));

        let destination_balance =
            state::may_load_token_balance(deps.as_ref().storage, &token_id, &destination_chain)
                .unwrap();
        assert_eq!(destination_balance, None);
    }

    #[test]
    fn balance_tracking_deploy_token_manager() {
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

        let token_id = TokenId::new([4u8; 32]);

        let deploy_message = ItsMessage::DeployTokenManager {
            token_id: token_id.clone(),
            token_manager_type: crate::primitives::TokenManagerType::MintBurn,
            params: HexBinary::from_hex("").unwrap(),
        };
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: deploy_message,
        };

        let payload = its_hub_message.abi_encode();
        let cc_id =
            CrossChainId::new(source_chain.clone(), "deploy-token-manager-message-id").unwrap();
        execute_message(deps.as_mut(), cc_id, source_address, payload).unwrap();

        // Check that balance tracking is not initialized for DeployTokenManager
        let source_balance =
            state::may_load_token_balance(deps.as_ref().storage, &token_id, &source_chain).unwrap();
        assert_eq!(source_balance, None);
        let destination_balance =
            state::may_load_token_balance(deps.as_ref().storage, &token_id, &destination_chain)
                .unwrap();
        assert_eq!(destination_balance, Some(TokenBalance::Untracked));
    }

    #[test]
    fn token_already_registered() {
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

        let token_id = TokenId::new([5u8; 32]);

        // First, deploy a token manager
        let deploy_manager_message = ItsMessage::DeployTokenManager {
            token_id: token_id.clone(),
            token_manager_type: crate::primitives::TokenManagerType::MintBurn,
            params: HexBinary::from_hex("").unwrap(),
        };
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: deploy_manager_message,
        };

        let payload = its_hub_message.abi_encode();
        let cc_id =
            CrossChainId::new(source_chain.clone(), "deploy-token-manager-message-id").unwrap();
        execute_message(deps.as_mut(), cc_id, source_address.clone(), payload).unwrap();

        // Now, try to deploy an interchain token with the same token_id
        let deploy_token_message = ItsMessage::DeployInterchainToken {
            token_id: token_id.clone(),
            name: "Test Token".to_string(),
            symbol: "TST".to_string(),
            decimals: 18,
            minter: HexBinary::from_hex("1234").unwrap(),
        };
        let its_hub_message = ItsHubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: deploy_token_message,
        };

        let payload = its_hub_message.abi_encode();
        let cc_id =
            CrossChainId::new(source_chain.clone(), "deploy-interchain-token-message-id").unwrap();
        let result = execute_message(deps.as_mut(), cc_id, source_address, payload);

        // The execution should fail because the token is already registered
        assert!(result.is_err());
        assert!(err_contains!(
            result.unwrap_err(),
            state::Error,
            state::Error::TokenAlreadyRegistered { .. }
        ));

        // Verify that the token balance remains untracked
        let balance =
            state::may_load_token_balance(deps.as_ref().storage, &token_id, &destination_chain)
                .unwrap();
        assert_eq!(balance, Some(TokenBalance::Untracked));
    }
}

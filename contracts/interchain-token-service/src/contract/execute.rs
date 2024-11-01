use axelar_wasm_std::{killswitch, nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::state::{
    self, is_chain_frozen, load_config, load_its_contract, MessageDirection, TokenDeploymentType,
};
use crate::{Message, TokenChainInfo, TokenConfig, TokenId};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("unknown chain {0}")]
    UnknownChain(ChainNameRaw),
    #[error("unknown its address {0}")]
    UnknownItsContract(Address),
    #[error("failed to decode payload")]
    InvalidPayload,
    #[error("invalid message type")]
    InvalidMessageType,
    #[error("failed to register its contract for chain {0}")]
    FailedItsContractRegistration(ChainNameRaw),
    #[error("failed to deregister its contract for chain {0}")]
    FailedItsContractDeregistration(ChainNameRaw),
    #[error("failed to execute message")]
    FailedExecuteMessage,
    #[error("execution is currently disabled")]
    ExecutionDisabled,
    #[error("chain {0} is frozen")]
    ChainFrozen(ChainNameRaw),
    #[error("state error")]
    State,
    #[error("chain config for {0} already set")]
    ChainConfigAlreadySet(ChainNameRaw),
    #[error("token info not found for token {0}")]
    TokenInfoNotFound(TokenId),
    #[error("token {token_id} not deployed on chain {chain}")]
    TokenNotDeployed {
        token_id: TokenId,
        chain: ChainNameRaw,
    },
    #[error("token {token_id} already deployed on chain {chain}")]
    TokenAlreadyDeployed {
        token_id: TokenId,
        chain: ChainNameRaw,
    },
    #[error("token {token_id} can only be deployed from its origin chain {origin_chain} and not from {chain}")]
    TokenDeployedFromNonOriginChain {
        token_id: TokenId,
        origin_chain: ChainNameRaw,
        chain: ChainNameRaw,
    },
    #[error("token supply invariant violated for token {token_id} on chain {chain}")]
    TokenSupplyInvariantViolated {
        token_id: TokenId,
        chain: ChainNameRaw,
    },
}

/// Executes an incoming ITS message.
///
/// This function handles the execution of ITS (Interchain Token Service) messages received from
/// its sources. It verifies the source address, decodes the message, applies various checks and transformations,
/// and forwards the message to the destination chain.
pub fn execute_message(
    deps: DepsMut,
    cc_id: CrossChainId,
    source_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    ensure!(
        killswitch::is_contract_active(deps.storage),
        Error::ExecutionDisabled
    );
    ensure_its_source_address(deps.storage, &cc_id.source_chain, &source_address)?;

    match HubMessage::abi_decode(&payload).change_context(Error::InvalidPayload)? {
        HubMessage::SendToHub {
            destination_chain,
            message,
        } => {
            let destination_address = load_its_contract(deps.storage, &destination_chain)
                .change_context_lazy(|| Error::UnknownChain(destination_chain.clone()))?;

            for message_direction in [
                MessageDirection::From(cc_id.source_chain.clone()),
                MessageDirection::To(destination_chain.clone()),
            ] {
                apply_checks(deps.storage, &message, message_direction)?;
            }

            let destination_payload = HubMessage::ReceiveFromHub {
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
                Event::MessageReceived {
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

fn ensure_chain_not_frozen(storage: &dyn Storage, chain: &ChainNameRaw) -> Result<(), Error> {
    ensure!(
        !is_chain_frozen(storage, chain).change_context(Error::State)?,
        Error::ChainFrozen(chain.to_owned())
    );

    Ok(())
}

fn normalize(chain: &ChainNameRaw) -> ChainName {
    ChainName::try_from(chain.as_ref()).expect("invalid chain name")
}

/// Ensures that the source address of the cross-chain message is the registered ITS contract for the source chain.
fn ensure_its_source_address(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    source_address: &Address,
) -> Result<(), Error> {
    let source_its_contract = load_its_contract(storage, source_chain)
        .change_context_lazy(|| Error::UnknownChain(source_chain.clone()))?;

    ensure!(
        source_address == &source_its_contract,
        Error::UnknownItsContract(source_address.clone())
    );

    Ok(())
}

fn send_to_destination(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: ChainNameRaw,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let config = load_config(storage);

    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(querier, &config.axelarnet_gateway).into();

    let call_contract_msg =
        gateway.call_contract(normalize(&destination_chain), destination_address, payload);

    Ok(Response::new().add_message(call_contract_msg))
}

pub fn register_its_contract(
    deps: DepsMut,
    chain: ChainNameRaw,
    address: Address,
) -> Result<Response, Error> {
    state::save_its_contract(deps.storage, &chain, &address)
        .change_context_lazy(|| Error::FailedItsContractRegistration(chain.clone()))?;

    Ok(Response::new().add_event(Event::ItsContractRegistered { chain, address }.into()))
}

pub fn deregister_its_contract(deps: DepsMut, chain: ChainNameRaw) -> Result<Response, Error> {
    state::remove_its_contract(deps.storage, &chain)
        .change_context_lazy(|| Error::FailedItsContractDeregistration(chain.clone()))?;

    Ok(Response::new().add_event(Event::ItsContractDeregistered { chain }.into()))
}

pub fn freeze_chain(deps: DepsMut, chain: ChainNameRaw) -> Result<Response, Error> {
    state::freeze_chain(deps.storage, &chain).change_context(Error::State)?;

    Ok(Response::new())
}

pub fn unfreeze_chain(deps: DepsMut, chain: ChainNameRaw) -> Result<Response, Error> {
    state::unfreeze_chain(deps.storage, &chain).change_context(Error::State)?;

    Ok(Response::new())
}

pub fn disable_execution(deps: DepsMut) -> Result<Response, Error> {
    killswitch::engage(deps.storage, Event::ExecutionDisabled).change_context(Error::State)
}

pub fn enable_execution(deps: DepsMut) -> Result<Response, Error> {
    killswitch::disengage(deps.storage, Event::ExecutionEnabled).change_context(Error::State)
}

pub fn set_chain_config(
    deps: DepsMut,
    chain: ChainNameRaw,
    max_uint: nonempty::Uint256,
    max_target_decimals: u8,
) -> Result<Response, Error> {
    match state::may_load_chain_config(deps.storage, &chain).change_context(Error::State)? {
        Some(_) => bail!(Error::ChainConfigAlreadySet(chain)),
        None => state::save_chain_config(deps.storage, &chain, max_uint, max_target_decimals)
            .change_context(Error::State)?
            .then(|_| Ok(Response::new())),
    }
}

/// Applies various checks on the message.
fn apply_checks(
    storage: &mut dyn Storage,
    message: &Message,
    message_direction: MessageDirection,
) -> Result<(), Error> {
    let token_chain_info = state::may_load_token_chain_info(
        storage,
        message_direction.clone().into(),
        message.token_id(),
    )
    .change_context(Error::State)?;

    // Validation checks
    ensure_chain_not_frozen(storage, &message_direction.clone().into())?;
    ensure_token_not_redeployed(message, &message_direction, token_chain_info.as_ref())?;
    ensure_token_deployed_from_origin_chain(storage, message, &message_direction, token_chain_info.as_ref())?;

    // Transformations
    let token_chain_info = track_token_supply(message, &message_direction, token_chain_info)?
        .then(|token_chain_info| {
        update_token_supply(message, &message_direction, token_chain_info)
    })?;

    state::save_token_chain_info(
        storage,
        message_direction.into(),
        message.token_id(),
        &token_chain_info,
    )
    .change_context(Error::State)
}

/// Ensures that the token is being redeployed from the same origin chain.
/// If it's being deployed for the first time, the from chain is saved as the origin chain in the token config.
fn ensure_token_deployed_from_origin_chain(
    storage: &mut dyn Storage,
    message: &Message,
    message_direction: &MessageDirection,
    token_chain_info: Option<&TokenChainInfo>,
) -> Result<(), Error> {
    // Token cannot be redeployed to the destination chain
    if !matches!(
        message,
        Message::DeployInterchainToken { .. } | Message::DeployTokenManager { .. }
    ) || !matches!(message_direction, MessageDirection::From(_))
    {
        return Ok(());
    }

    let token_config =
        state::may_load_token_config(storage, &message.token_id()).change_context(Error::State)?;

    if let Some(TokenConfig { origin_chain, .. }) = token_config {
        // Token can only be redeployed from the same origin chain
        ensure!(
            origin_chain == ChainNameRaw::from(message_direction.clone()),
            Error::TokenDeployedFromNonOriginChain {
                token_id: message.token_id(),
                origin_chain,
                chain: message_direction.clone().into(),
            }
        );

        // Token chain info must already exist from previous deployment
        ensure!(
            token_chain_info.is_some(),
            Error::TokenNotDeployed {
                token_id: message.token_id(),
                chain: message_direction.clone().into(),
            }
        );
    } else {
        // Token is being deployed for the first time
        let token_config = TokenConfig {
            origin_chain: ChainNameRaw::from(message_direction.clone()),
        };

        state::save_token_config(storage, &message.token_id(), &token_config)
            .change_context(Error::State)?;

        ensure!(
            token_chain_info.is_none(),
            Error::TokenAlreadyDeployed {
                token_id: message.token_id(),
                chain: message_direction.clone().into(),
            }
        );
    }

    Ok(())
}

/// Ensures that the token is not being redeployed to the same destination chain.
fn ensure_token_not_redeployed(
    message: &Message,
    message_direction: &MessageDirection,
    token_chain_info: Option<&TokenChainInfo>,
) -> Result<(), Error> {
    if matches!(
        message,
        Message::DeployInterchainToken { .. } | Message::DeployTokenManager { .. }
    ) && matches!(message_direction, MessageDirection::To(_))
        && token_chain_info.is_some()
    {
        bail!(Error::TokenAlreadyDeployed {
            token_id: message.token_id(),
            chain: message_direction.clone().into(),
        });
    }

    Ok(())
}

/// Ensures that the token info is recorded on deployment.
/// The token supply tracking is also enabled on deployment for trustless token deployments (i.e no minter set).
/// Tokens that haven't been deployed yet cannot be transferred.
fn track_token_supply(
    message: &Message,
    message_direction: &MessageDirection,
    token_chain_info: Option<TokenChainInfo>,
) -> Result<TokenChainInfo, Error> {
    if let Some(token_chain_info) = token_chain_info {
        return Ok(token_chain_info);
    }

    let token_deployment_type = match message {
        Message::DeployInterchainToken { minter: None, .. } => TokenDeploymentType::Trustless,
        Message::DeployInterchainToken { .. } | Message::DeployTokenManager { .. } => {
            TokenDeploymentType::CustomMinter
        }
        Message::InterchainTransfer { .. } => bail!(Error::TokenNotDeployed {
            token_id: message.token_id(),
            chain: message_direction.clone().into(),
        }),
    };

    Ok(TokenChainInfo::new(
        (message_direction, token_deployment_type).into(),
    ))
}

/// Updates the token supply for the chain on a transfer.
/// Ensures that the transfer `amount <= supply` for the chain,
/// i.e no more than the token supply for the chain can be transferred out of the chain.
fn update_token_supply(
    message: &Message,
    message_direction: &MessageDirection,
    mut token_chain_info: TokenChainInfo,
) -> Result<TokenChainInfo, Error> {
    if let Message::InterchainTransfer {
        token_id, amount, ..
    } = message
    {
        token_chain_info
            .update_supply(*amount, message_direction.clone())
            .change_context_lazy(|| Error::TokenSupplyInvariantViolated {
                token_id: token_id.clone(),
                chain: message_direction.clone().into(),
            })?;
    }

    Ok(token_chain_info)
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::{assert_err_contains, killswitch, nonempty, permission_control};
    use cosmwasm_std::testing::{mock_dependencies, MockApi, MockQuerier};
    use cosmwasm_std::{Addr, HexBinary, MemoryStorage, OwnedDeps, Uint256};
    use router_api::{ChainNameRaw, CrossChainId};

    use crate::contract::execute::{
        disable_execution, enable_execution, execute_message, freeze_chain, register_its_contract,
        set_chain_config, unfreeze_chain, Error,
    };
    use crate::state::{self, Config};
    use crate::{HubMessage, Message};

    const SOLANA: &str = "solana";
    const ETHEREUM: &str = "ethereum";
    const XRPL: &str = "xrpl";

    const ITS_ADDRESS: &str = "68d30f47F19c07bCCEf4Ac7FAE2Dc12FCa3e0dC9";

    const ADMIN: &str = "admin";
    const GOVERNANCE: &str = "governance";
    const AXELARNET_GATEWAY: &str = "axelarnet-gateway";

    fn its_address() -> nonempty::HexBinary {
        HexBinary::from_hex(ITS_ADDRESS)
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn should_be_able_to_disable_and_enable_execution() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let msg = HubMessage::SendToHub {
            destination_chain: ChainNameRaw::try_from(SOLANA).unwrap(),
            message: Message::DeployInterchainToken {
                token_id: [7u8; 32].into(),
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            },
        };
        let cc_id = CrossChainId {
            source_chain: ChainNameRaw::try_from(ETHEREUM).unwrap(),
            message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32).into(),
        };

        assert_ok!(execute_message(
            deps.as_mut(),
            cc_id.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.clone().abi_encode(),
        ));

        assert_ok!(disable_execution(deps.as_mut()));

        let msg = HubMessage::SendToHub {
            destination_chain: ChainNameRaw::try_from(SOLANA).unwrap(),
            message: Message::InterchainTransfer {
                token_id: [7u8; 32].into(),
                amount: Uint256::one().try_into().unwrap(),
                source_address: its_address(),
                destination_address: its_address(),
                data: None,
            },
        };

        let res = execute_message(
            deps.as_mut(),
            cc_id.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.clone().abi_encode(),
        );
        assert_err_contains!(res, Error, Error::ExecutionDisabled);

        assert_ok!(enable_execution(deps.as_mut()));

        let msg = HubMessage::SendToHub {
            destination_chain: ChainNameRaw::try_from(SOLANA).unwrap(),
            message: Message::DeployInterchainToken {
                token_id: [1u8; 32].into(),
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            },
        };
        assert_ok!(execute_message(
            deps.as_mut(),
            cc_id.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.abi_encode(),
        ));
    }

    #[test]
    fn execution_should_fail_if_source_chain_is_frozen() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let source_chain = ChainNameRaw::try_from(SOLANA).unwrap();
        let destination_chain = ChainNameRaw::try_from(ETHEREUM).unwrap();

        assert_ok!(freeze_chain(deps.as_mut(), source_chain.clone()));

        let msg = HubMessage::SendToHub {
            destination_chain,
            message: Message::DeployInterchainToken {
                token_id: [7u8; 32].into(),
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            },
        };
        let res = execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.clone().abi_encode(),
        );

        assert_err_contains!(res, Error, Error::ChainFrozen(..));

        assert_ok!(unfreeze_chain(deps.as_mut(), source_chain.clone()));

        assert_ok!(execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain,
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.clone().abi_encode(),
        ));
    }

    #[test]
    fn execution_should_fail_if_destination_chain_is_frozen() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let source_chain = ChainNameRaw::try_from(SOLANA).unwrap();
        let destination_chain = ChainNameRaw::try_from(ETHEREUM).unwrap();

        assert_ok!(freeze_chain(deps.as_mut(), destination_chain.clone()));

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::DeployInterchainToken {
                token_id: [7u8; 32].into(),
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            },
        };
        let cc_id = CrossChainId {
            source_chain,
            message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                .to_string()
                .try_into()
                .unwrap(),
        };

        let res = execute_message(
            deps.as_mut(),
            cc_id.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.clone().abi_encode(),
        );
        assert_err_contains!(res, Error, Error::ChainFrozen(..));

        assert_ok!(unfreeze_chain(deps.as_mut(), destination_chain));

        assert_ok!(execute_message(
            deps.as_mut(),
            cc_id,
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.clone().abi_encode(),
        ));
    }

    #[test]
    fn frozen_chain_that_is_not_source_or_destination_should_not_affect_execution() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let source_chain = ChainNameRaw::try_from(SOLANA).unwrap();
        let destination_chain = ChainNameRaw::try_from(ETHEREUM).unwrap();
        let other_chain = ChainNameRaw::try_from(XRPL).unwrap();

        assert_ok!(freeze_chain(deps.as_mut(), other_chain.clone()));

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: Message::DeployInterchainToken {
                token_id: [7u8; 32].into(),
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            },
        };
        let cc_id = CrossChainId {
            source_chain,
            message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                .to_string()
                .try_into()
                .unwrap(),
        };

        assert_ok!(execute_message(
            deps.as_mut(),
            cc_id.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.clone().abi_encode(),
        ));
    }

    fn init(deps: &mut OwnedDeps<MemoryStorage, MockApi, MockQuerier>) {
        assert_ok!(permission_control::set_admin(
            deps.as_mut().storage,
            &Addr::unchecked(ADMIN)
        ));
        assert_ok!(permission_control::set_governance(
            deps.as_mut().storage,
            &Addr::unchecked(GOVERNANCE)
        ));

        assert_ok!(state::save_config(
            deps.as_mut().storage,
            &Config {
                axelarnet_gateway: Addr::unchecked(AXELARNET_GATEWAY),
            },
        ));

        assert_ok!(killswitch::init(
            deps.as_mut().storage,
            killswitch::State::Disengaged
        ));

        for chain_name in [SOLANA, ETHEREUM, XRPL] {
            let chain = ChainNameRaw::try_from(chain_name).unwrap();
            assert_ok!(register_its_contract(
                deps.as_mut(),
                chain.clone(),
                ITS_ADDRESS.to_string().try_into().unwrap(),
            ));
            assert_ok!(set_chain_config(
                deps.as_mut(),
                chain,
                Uint256::one().try_into().unwrap(),
                16u8
            ));
        }
    }
}

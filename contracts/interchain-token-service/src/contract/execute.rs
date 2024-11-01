use axelar_wasm_std::{killswitch, nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::state::{self, load_config, load_its_contract, DirectionalChain, TokenDeploymentType};
use crate::{Message, TokenId, TokenInfo, TokenType};

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
    #[error("chain config for {0} already set")]
    ChainConfigAlreadySet(ChainNameRaw),
    #[error("failed to load chain config for chain {0}")]
    LoadChainConfig(ChainNameRaw),
    #[error("failed to save chain config for chain {0}")]
    SaveChainConfig(ChainNameRaw),
    #[error("failed to save token info for token {0}")]
    SaveTokenInfo(TokenId),
    #[error("failed to load token info for token {0}")]
    LoadTokenInfo(TokenId),
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
    #[error("state error")]
    State,
    #[error("balance invariant violated for token {token_id} on chain {chain}")]
    TokenBalanceInvariantViolated {
        token_id: TokenId,
        chain: ChainNameRaw,
    },
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

            apply_handlers(deps.storage, &message, DirectionalChain::Source(cc_id.source_chain.clone()))?;
            apply_handlers(deps.storage, &message, DirectionalChain::Destination(destination_chain.clone()))?;

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
    match state::may_load_chain_config(deps.storage, &chain)
        .change_context_lazy(|| Error::LoadChainConfig(chain.clone()))?
    {
        Some(_) => bail!(Error::ChainConfigAlreadySet(chain)),
        None => state::save_chain_config(deps.storage, &chain, max_uint, max_target_decimals)
            .change_context_lazy(|| Error::SaveChainConfig(chain))?
            .then(|_| Ok(Response::new())),
    }
}

fn apply_handlers(
    storage: &mut dyn Storage,
    message: &Message,
    directional_chain: DirectionalChain,
) -> Result<(), Error> {
    let token_info = state::may_load_token_info(storage, directional_chain.clone().into(), message.token_id())
        .change_context_lazy(|| Error::LoadTokenInfo(message.token_id()))?;

    // Note: The order of the handlers is important
    let token_info = token_info
        .then(|token_info| token_redeployment_check(message, &directional_chain, token_info))?
        .then(|token_info| token_deployment_handler(message, &directional_chain, token_info))?
        .then(|token_info| token_balance_handler(message, &directional_chain, token_info))?;

    state::save_token_info(storage, directional_chain.into(), message.token_id(), token_info)
        .change_context_lazy(|| Error::SaveTokenInfo(message.token_id()))
}

fn token_redeployment_check(
    message: &Message,
    directional_chain: &DirectionalChain,
    token_info: Option<TokenInfo>,
) -> Result<Option<TokenInfo>, Error> {
    match (&token_info, message) {
        (None, Message::InterchainTransfer { token_id, .. }) => bail!(Error::TokenNotDeployed {
            token_id: token_id.clone(),
            chain: directional_chain.clone().into(),
        }),
        (Some(_), Message::DeployInterchainToken { token_id, .. } | Message::DeployTokenManager { token_id, .. }) if TokenType::from(directional_chain) != TokenType::Origin => {
            bail!(Error::TokenAlreadyDeployed {
                token_id: token_id.clone(),
                chain: directional_chain.clone().into(),
            })
        },
        _ => Ok(token_info),
    }
}

fn token_deployment_handler(
    message: &Message,
    directional_chain: &DirectionalChain,
    token_info: Option<TokenInfo>,
) -> Result<TokenInfo, Error> {
    let token_deployment_type = match (token_info, message) {
        (Some(token_info), _) => return Ok(token_info),
        (None, Message::DeployInterchainToken { minter: None, .. }) => {
            TokenDeploymentType::Trustless
        },
        (None, Message::DeployInterchainToken { .. } | Message::DeployTokenManager { .. }) => {
            TokenDeploymentType::CustomMinter
        },
        // TODO: Should we panic on this since the previous handler will check it, or should we merge the handlers to avoid this scenario, albeit adding a bit more complexity?
        (None, _) => bail!(Error::TokenNotDeployed {
            token_id: message.token_id(),
            chain: directional_chain.clone().into(),
        }),
    };

    let token_type: TokenType = directional_chain.into();
    let balance = (token_type.clone(), token_deployment_type).into();

    Ok(TokenInfo {
        balance,
        token_type,
    })
}

fn token_balance_handler(
    message: &Message,
    directional_chain: &DirectionalChain,
    mut token_info: TokenInfo,
) -> Result<TokenInfo, Error> {
    if let Message::InterchainTransfer {
            token_id, amount, ..
        } = message {
            token_info.update_balance(*amount, directional_chain.clone())
                .change_context_lazy(|| Error::TokenBalanceInvariantViolated {
                    token_id: token_id.clone(),
                    chain: directional_chain.clone().into(),
                })?;
        }

    Ok(token_info)
}

/// Applies invariants on the ITS message.
///
/// Invariants:
/// - Token must be deployed on the chain before any transfers can be routed.
/// - Token cannot be redeployed to the chain.
/// - If the token is deployed without a custom minter, then the token is considered to be owned by ITS, and total token balance moved to the chain is tracked.
/// - If the total token amount moved to a chain so far is `x`, then any transfer moving the token back from the chain and exceeding `x` will fail.
///
/// Invariants are updated depending on the ITS message type
///
/// 1. InterchainTransfer:
///    - Decreases the token balance on the source chain if the balance is being tracked.
///    - Increases the token balance on the destination chain if the balance is being tracked.
///    - If the balance underflows for either case, an error is returned.
///
/// 2. DeployInterchainToken:
///    - If a custom minter is not set, then the token balance is tracked for the destination chain.
///    - If a custom minter is set, then the balance is not tracked, but the deployment is recorded as `TokenInfo`.
///
/// 3. DeployTokenManager:
///    - Same as the custom minter being set above. ITS Hub can't know if the existing token on the destination chain has a custom minter set.
// fn apply_balance_invariant(
//     storage: &mut dyn Storage,
//     message: &Message,
//     directional_chain: DirectionalChain,
// ) -> Result<(), Error> {
//     match message {
//         Message::InterchainTransfer {
//             token_id, amount, ..
//         } => {
//             state::update_token_info(storage, directional_chain, token_id.clone(), *amount)
//                 .change_context_lazy(|| Error::UpdateTokenInfo(token_id.clone()))?;
//         }
//         Message::DeployInterchainToken {
//             token_id,
//             minter: None,
//             ..
//         } => {
//             state::save_token_info(
//                 storage,
//                 directional_chain,
//                 token_id.clone(),
//                 TokenDeploymentType::Trustless,
//             )
//             .change_context_lazy(|| Error::SaveTokenInfo(token_id.clone()))?;
//         }
//         Message::DeployInterchainToken {
//             token_id,
//             minter: Some(_),
//             ..
//         }
//         | Message::DeployTokenManager { token_id, .. } => {
//             state::save_token_info(
//                 storage,
//                 directional_chain,
//                 token_id.clone(),
//                 TokenDeploymentType::CustomMinter,
//             )
//             .change_context_lazy(|| Error::SaveTokenInfo(token_id.clone()))?;
//         }
//     };

//     Ok(())
// }

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::{assert_err_contains, killswitch, nonempty, permission_control};
    use cosmwasm_std::testing::{mock_dependencies, MockApi, MockQuerier};
    use cosmwasm_std::{Addr, HexBinary, MemoryStorage, OwnedDeps, Uint256};
    use router_api::{ChainNameRaw, CrossChainId};

    use super::disable_execution;
    use crate::contract::execute::{
        enable_execution, execute_message, register_its_contract, Error,
    };
    use crate::state::{self, Config};
    use crate::{HubMessage, Message};

    const SOLANA: &str = "solana";
    const ETHEREUM: &str = "ethereum";

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
        let amplifier_chain = ChainNameRaw::try_from(SOLANA).unwrap();
        let core_chain = ChainNameRaw::try_from(ETHEREUM).unwrap();

        assert_ok!(register_its_contract(
            deps.as_mut(),
            core_chain.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
        ));

        assert_ok!(register_its_contract(
            deps.as_mut(),
            amplifier_chain.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
        ));
    }
}

use axelar_wasm_std::{killswitch, nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::state::{self, load_config, load_its_contract};
use crate::{Message, TokenId};

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
    #[error("failed to apply invariants for token {0}")]
    InvariantViolated(TokenId),
    #[error("state error")]
    State,
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

            apply_balance_invariant(deps.storage, &message, cc_id.source_chain.clone(), true)?;

            apply_balance_invariant(deps.storage, &message, destination_chain.clone(), false)?;

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
///    - Decreases the token balance on the source chain, unless it's the origin chain in which case it's increased.
///    - Increases the token balance on the destination chain, unless it's the origin chain in which case it's decreased.
///    - If the balance underflows for either case, an error is returned.
///
/// 2. DeployInterchainToken:
///    - If a custom minter is not set, then the token balance is tracked for the source/destination chain.
///    - If the custom minter is set, then the balance is not tracked, but the deployment is recorded.
///
/// 3. DeployTokenManager:
///    - Same as the custom minter being set above. ITS Hub can't know if the existing token on the destination chain has a custom minter set.
fn apply_balance_invariant(
    storage: &mut dyn Storage,
    message: &Message,
    chain: ChainNameRaw,
    is_source_chain: bool,
) -> Result<(), Error> {
    match message {
        Message::InterchainTransfer {
            token_id, amount, ..
        } => {
            state::update_token_info(
                storage,
                chain.clone(),
                token_id.clone(),
                *amount,
                !is_source_chain,
            )
            .change_context_lazy(|| Error::InvariantViolated(token_id.clone()))?;
        }
        Message::DeployInterchainToken {
            token_id,
            minter: None,
            ..
        } => {
            state::save_token_info(
                storage,
                chain.clone(),
                token_id.clone(),
                is_source_chain,
                true,
            )
            .change_context_lazy(|| Error::InvariantViolated(token_id.clone()))?;
        }
        Message::DeployInterchainToken {
            token_id,
            minter: Some(_),
            ..
        }
        | Message::DeployTokenManager { token_id, .. } => {
            state::save_token_info(
                storage,
                chain.clone(),
                token_id.clone(),
                is_source_chain,
                false,
            )
            .change_context_lazy(|| Error::InvariantViolated(token_id.clone()))?;
        }
    };

    Ok(())
}

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

use axelar_wasm_std::{killswitch, nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage, Uint256};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::state::{self, is_chain_frozen, load_config, load_its_contract};
use crate::Message;

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
    #[error("chain {0} is frozen")]
    ChainFrozen(ChainNameRaw),
    #[error(
        "invalid transfer amount {amount} from chain {source_chain} to chain {destination_chain}"
    )]
    InvalidTransferAmount {
        source_chain: ChainNameRaw,
        destination_chain: ChainNameRaw,
        amount: nonempty::Uint256,
    },
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

            verify_chains_not_frozen(deps.storage, &cc_id.source_chain, &destination_chain)?;

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

fn verify_chains_not_frozen(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
) -> Result<(), Error> {
    for chain in [source_chain, destination_chain] {
        if is_chain_frozen(storage, chain).change_context(Error::State)? {
            return Err(report!(Error::ChainFrozen(chain.to_owned())));
        }
    }
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
    match state::may_load_chain_config(deps.storage, &chain)
        .change_context_lazy(|| Error::LoadChainConfig(chain.clone()))?
    {
        Some(_) => bail!(Error::ChainConfigAlreadySet(chain)),
        None => state::save_chain_config(deps.storage, &chain, max_uint, max_target_decimals)
            .change_context_lazy(|| Error::SaveChainConfig(chain))?
            .then(|_| Ok(Response::new())),
    }
}

#[allow(unused)]
fn translate_amount_on_token_transfer(
    storage: &dyn Storage,
    src_chain: &ChainNameRaw,
    dest_chain: &ChainNameRaw,
    message: Message,
) -> Result<Message, Error> {
    match message {
        Message::InterchainTransfer {
            token_id,
            source_address,
            destination_address,
            amount,
            data,
        } => {
            let src_chain_decimals = state::load_token_decimals(storage, src_chain, token_id)
                .change_context(Error::State)?;
            let dest_chain_decimals = state::load_token_decimals(storage, dest_chain, token_id)
                .change_context(Error::State)?;
            let dest_chain_config =
                state::load_chain_config(storage, dest_chain).change_context(Error::State)?;

            // dest_chain_amount = amount * 10 ^ (dest_chain_decimals - src_chain_decimals)
            // It's intentionally written in this way since the end result may still be fine even if
            //     1) amount * (10 ^ (dest_chain_decimals)) overflows
            //     2) amount / (10 ^ (src_chain_decimals)) is zero
            let dest_chain_amount = if src_chain_decimals > dest_chain_decimals {
                amount
                    .checked_div(
                        Uint256::from_u128(10)
                            .checked_pow(
                                src_chain_decimals
                                    .checked_sub(dest_chain_decimals)
                                    .expect("decimals subtraction overflow")
                                    .into(),
                            )
                            .change_context_lazy(|| Error::InvalidTransferAmount {
                                source_chain: src_chain.to_owned(),
                                destination_chain: dest_chain.to_owned(),
                                amount,
                            })?,
                    )
                    .expect("(10 ^ (src_chain_decimals-dest_chain_decimals)) must be non-zero")
            } else {
                amount
                    .checked_mul(
                        Uint256::from_u128(10)
                            .checked_pow(
                                dest_chain_decimals
                                    .checked_sub(src_chain_decimals)
                                    .expect("decimals subtraction overflow")
                                    .into(),
                            )
                            .change_context_lazy(|| Error::InvalidTransferAmount {
                                source_chain: src_chain.to_owned(),
                                destination_chain: dest_chain.to_owned(),
                                amount,
                            })?,
                    )
                    .change_context_lazy(|| Error::InvalidTransferAmount {
                        source_chain: src_chain.to_owned(),
                        destination_chain: dest_chain.to_owned(),
                        amount,
                    })?
            };

            if dest_chain_amount.gt(&dest_chain_config.max_uint) {
                bail!(Error::InvalidTransferAmount {
                    source_chain: src_chain.to_owned(),
                    destination_chain: dest_chain.to_owned(),
                    amount,
                })
            }

            Ok(Message::InterchainTransfer {
                token_id,
                source_address,
                destination_address,
                amount: nonempty::Uint256::try_from(dest_chain_amount).change_context_lazy(
                    || Error::InvalidTransferAmount {
                        source_chain: src_chain.to_owned(),
                        destination_chain: dest_chain.to_owned(),
                        amount,
                    },
                )?,
                data,
            })
        }
        _ => Ok(message),
    }
}

#[allow(unused)]
fn translate_and_save_token_decimals_on_token_deployment(
    storage: &mut dyn Storage,
    src_chain: &ChainNameRaw,
    dest_chain: &ChainNameRaw,
    message: Message,
) -> Result<Message, Error> {
    match message {
        Message::DeployInterchainToken {
            token_id,
            name,
            symbol,
            decimals: src_chain_decimals,
            minter,
        } => {
            let src_chain_config =
                state::load_chain_config(storage, src_chain).change_context(Error::State)?;
            let dest_chain_config =
                state::load_chain_config(storage, dest_chain).change_context(Error::State)?;

            let dest_chain_decimals = if src_chain_config.max_uint.le(&dest_chain_config.max_uint) {
                src_chain_decimals
            } else {
                src_chain_config.max_target_decimals.min(src_chain_decimals)
            };

            state::save_token_decimals(storage, src_chain, token_id, src_chain_decimals)
                .change_context(Error::State)?;
            state::save_token_decimals(storage, dest_chain, token_id, dest_chain_decimals)
                .change_context(Error::State)?;

            Ok(Message::DeployInterchainToken {
                token_id,
                name,
                symbol,
                decimals: dest_chain_decimals,
                minter,
            })
        }
        _ => Ok(message),
    }
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

        assert_ok!(disable_execution(deps.as_mut()));

        let msg = HubMessage::SendToHub {
            destination_chain: ChainNameRaw::try_from(SOLANA).unwrap(),
            message: Message::InterchainTransfer {
                token_id: [7u8; 32].into(),
                source_address: its_address(),
                destination_address: its_address(),
                amount: Uint256::one().try_into().unwrap(),
                data: None,
            },
        };
        let res = execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: ChainNameRaw::try_from(SOLANA).unwrap(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            msg.clone().abi_encode(),
        );
        assert_err_contains!(res, Error, Error::ExecutionDisabled);

        assert_ok!(enable_execution(deps.as_mut()));

        assert_ok!(execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: ChainNameRaw::try_from(SOLANA).unwrap(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
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
            message: Message::InterchainTransfer {
                token_id: [7u8; 32].into(),
                source_address: its_address(),
                destination_address: its_address(),
                amount: Uint256::one().try_into().unwrap(),
                data: None,
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
            message: Message::InterchainTransfer {
                token_id: [7u8; 32].into(),
                source_address: its_address(),
                destination_address: its_address(),
                amount: Uint256::one().try_into().unwrap(),
                data: None,
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
            message: Message::InterchainTransfer {
                token_id: [7u8; 32].into(),
                source_address: its_address(),
                destination_address: its_address(),
                amount: Uint256::one().try_into().unwrap(),
                data: None,
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

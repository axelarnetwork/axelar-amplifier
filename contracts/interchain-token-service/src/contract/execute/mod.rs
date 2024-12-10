use axelar_wasm_std::{killswitch, nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage};
use error_stack::{bail, ensure, report, Result, ResultExt};
use itertools::Itertools;
use router_api::{Address, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::{msg, state, DeployInterchainToken, InterchainTransfer, Message, TokenId};

mod interceptors;

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("chain not found {0}")]
    ChainNotFound(ChainNameRaw),
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
    #[error("chain {0} already registered")]
    ChainAlreadyRegistered(ChainNameRaw),
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
    #[error(
        "token {token_id} deployed from chain {chain} with different decimals than original deployment"
    )]
    TokenDeployedDecimalsMismatch {
        token_id: TokenId,
        chain: ChainNameRaw,
        expected: u8,
        actual: u8,
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
    ensure_is_its_source_address(deps.storage, &cc_id.source_chain, &source_address)?;

    match HubMessage::abi_decode(&payload).change_context(Error::InvalidPayload)? {
        HubMessage::SendToHub {
            destination_chain,
            message,
        } => execute_message_on_hub(deps, cc_id, destination_chain, message),
        _ => bail!(Error::InvalidMessageType),
    }
}

fn execute_message_on_hub(
    deps: DepsMut,
    cc_id: CrossChainId,
    destination_chain: ChainNameRaw,
    message: Message,
) -> Result<Response, Error> {
    let destination_address = state::load_its_contract(deps.storage, &destination_chain)
        .change_context_lazy(|| Error::ChainNotFound(destination_chain.clone()))?;

    let message = apply_to_hub(
        deps.storage,
        cc_id.source_chain.clone(),
        destination_chain.clone(),
        message,
    )?;

    let destination_payload = HubMessage::ReceiveFromHub {
        source_chain: cc_id.source_chain.clone(),
        message: message.clone(),
    }
    .abi_encode();

    Ok(send_to_destination(
        deps.storage,
        deps.querier,
        &destination_chain,
        destination_address,
        destination_payload,
    )?
    .add_event(Event::MessageReceived {
        cc_id,
        destination_chain,
        message,
    }))
}

fn apply_to_hub(
    storage: &mut dyn Storage,
    source_chain: ChainNameRaw,
    destination_chain: ChainNameRaw,
    message: Message,
) -> Result<Message, Error> {
    ensure_chain_not_frozen(storage, &source_chain)?;
    ensure_chain_not_frozen(storage, &destination_chain)?;

    match message {
        Message::InterchainTransfer(transfer) => {
            apply_to_transfer(storage, source_chain, destination_chain, transfer)
                .map(Message::InterchainTransfer)?
        }
        Message::DeployInterchainToken(deploy_token) => {
            apply_to_token_deployment(storage, &source_chain, &destination_chain, deploy_token)
                .map(Message::DeployInterchainToken)?
        }
    }
    .then(Result::Ok)
}

fn apply_to_transfer(
    storage: &mut dyn Storage,
    source_chain: ChainNameRaw,
    destination_chain: ChainNameRaw,
    transfer: InterchainTransfer,
) -> Result<InterchainTransfer, Error> {
    interceptors::subtract_supply_amount(storage, &source_chain, &transfer)?;
    let transfer = interceptors::apply_scaling_factor_to_amount(
        storage,
        &source_chain,
        &destination_chain,
        transfer,
    )?;
    interceptors::add_supply_amount(storage, &destination_chain, &transfer)?;

    Ok(transfer)
}

fn apply_to_token_deployment(
    storage: &mut dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
    deploy_token: DeployInterchainToken,
) -> Result<DeployInterchainToken, Error> {
    interceptors::deploy_token_to_source_chain(storage, source_chain, &deploy_token)?;
    let deploy_token = interceptors::calculate_scaling_factor(
        storage,
        source_chain,
        destination_chain,
        deploy_token,
    )?;
    interceptors::deploy_token_to_destination_chain(storage, destination_chain, &deploy_token)?;

    Ok(deploy_token)
}

fn ensure_chain_not_frozen(storage: &dyn Storage, chain: &ChainNameRaw) -> Result<(), Error> {
    ensure!(
        !state::is_chain_frozen(storage, chain).change_context(Error::State)?,
        Error::ChainFrozen(chain.to_owned())
    );

    Ok(())
}

/// Ensures that the source address of the cross-chain message is the registered ITS contract for the source chain.
fn ensure_is_its_source_address(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    source_address: &Address,
) -> Result<(), Error> {
    let source_its_contract = state::load_its_contract(storage, source_chain)
        .change_context_lazy(|| Error::ChainNotFound(source_chain.clone()))?;

    ensure!(
        source_address == &source_its_contract,
        Error::UnknownItsContract(source_address.clone())
    );

    Ok(())
}

fn send_to_destination(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: &ChainNameRaw,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let config = state::load_config(storage);

    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(querier, &config.axelarnet_gateway).into();

    let call_contract_msg =
        gateway.call_contract(destination_chain.normalize(), destination_address, payload);

    Ok(Response::new().add_message(call_contract_msg))
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

pub fn register_chains(deps: DepsMut, chains: Vec<msg::ChainConfig>) -> Result<Response, Error> {
    chains
        .into_iter()
        .map(|chain_config| register_chain(deps.storage, chain_config))
        .try_collect::<_, Vec<Response>, _>()?
        .then(|_| Ok(Response::new()))
}

fn register_chain(storage: &mut dyn Storage, config: msg::ChainConfig) -> Result<Response, Error> {
    match state::may_load_chain_config(storage, &config.chain).change_context(Error::State)? {
        Some(_) => bail!(Error::ChainAlreadyRegistered(config.chain)),
        None => state::save_chain_config(storage, &config.chain.clone(), config)
            .change_context(Error::State)?
            .then(|_| Ok(Response::new())),
    }
}

pub fn update_chain(
    deps: DepsMut,
    chain: ChainNameRaw,
    its_address: Address,
) -> Result<Response, Error> {
    state::update_its_contract(deps.storage, &chain, its_address).change_context(Error::State)?;
    Ok(Response::new())
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::{assert_err_contains, killswitch, nonempty, permission_control};
    use cosmwasm_std::testing::{mock_dependencies, MockApi, MockQuerier};
    use cosmwasm_std::{HexBinary, MemoryStorage, OwnedDeps, Uint256};
    use router_api::{ChainNameRaw, CrossChainId};

    use crate::contract::execute::{
        disable_execution, enable_execution, execute_message, freeze_chain, register_chain,
        register_chains, unfreeze_chain, update_chain, Error,
    };
    use crate::msg::TruncationConfig;
    use crate::state::{self, Config};
    use crate::{msg, DeployInterchainToken, HubMessage, InterchainTransfer};

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
            message: DeployInterchainToken {
                token_id: [7u8; 32].into(),
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            }
            .into(),
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
            message: InterchainTransfer {
                token_id: [7u8; 32].into(),
                amount: Uint256::one().try_into().unwrap(),
                source_address: its_address(),
                destination_address: its_address(),
                data: None,
            }
            .into(),
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
            message: DeployInterchainToken {
                token_id: [1u8; 32].into(),
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            }
            .into(),
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
            message: DeployInterchainToken {
                token_id: [7u8; 32].into(),
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            }
            .into(),
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
            message: DeployInterchainToken {
                token_id: [7u8; 32].into(),
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            }
            .into(),
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
            message: DeployInterchainToken {
                token_id: [7u8; 32].into(),
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            }
            .into(),
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

    #[test]
    fn register_chain_fails_if_already_registered() {
        let mut deps = mock_dependencies();
        assert_ok!(register_chain(
            deps.as_mut().storage,
            msg::ChainConfig {
                chain: SOLANA.parse().unwrap(),
                its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                truncation: TruncationConfig {
                    max_uint: Uint256::one().try_into().unwrap(),
                    max_decimals_when_truncating: 16u8
                }
            }
        ));
        assert_err_contains!(
            register_chain(
                deps.as_mut().storage,
                msg::ChainConfig {
                    chain: SOLANA.parse().unwrap(),
                    its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint: Uint256::one().try_into().unwrap(),
                        max_decimals_when_truncating: 16u8
                    }
                }
            ),
            Error,
            Error::ChainAlreadyRegistered(..)
        );
    }

    #[test]
    fn register_chains_fails_if_any_already_registered() {
        let mut deps = mock_dependencies();
        let chains = vec![
            msg::ChainConfig {
                chain: SOLANA.parse().unwrap(),
                its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                truncation: TruncationConfig {
                    max_uint: Uint256::MAX.try_into().unwrap(),
                    max_decimals_when_truncating: 16u8,
                },
            },
            msg::ChainConfig {
                chain: XRPL.parse().unwrap(),
                its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                truncation: TruncationConfig {
                    max_uint: Uint256::MAX.try_into().unwrap(),
                    max_decimals_when_truncating: 16u8,
                },
            },
        ];
        assert_ok!(register_chains(deps.as_mut(), chains[0..1].to_vec()));
        assert_err_contains!(
            register_chains(deps.as_mut(), chains,),
            Error,
            Error::ChainAlreadyRegistered(..)
        );
    }

    #[test]
    fn update_chain_fails_if_not_registered() {
        let mut deps = mock_dependencies();
        assert_err_contains!(
            update_chain(
                deps.as_mut(),
                SOLANA.parse().unwrap(),
                ITS_ADDRESS.parse().unwrap()
            ),
            Error,
            Error::State
        );
    }

    fn init(deps: &mut OwnedDeps<MemoryStorage, MockApi, MockQuerier>) {
        assert_ok!(permission_control::set_admin(
            deps.as_mut().storage,
            &MockApi::default().addr_make(ADMIN)
        ));
        assert_ok!(permission_control::set_governance(
            deps.as_mut().storage,
            &MockApi::default().addr_make(GOVERNANCE)
        ));

        assert_ok!(state::save_config(
            deps.as_mut().storage,
            &Config {
                axelarnet_gateway: MockApi::default().addr_make(AXELARNET_GATEWAY),
            },
        ));

        assert_ok!(killswitch::init(
            deps.as_mut().storage,
            killswitch::State::Disengaged
        ));

        for chain_name in [SOLANA, ETHEREUM, XRPL] {
            let chain = ChainNameRaw::try_from(chain_name).unwrap();
            assert_ok!(register_chain(
                deps.as_mut().storage,
                msg::ChainConfig {
                    chain: chain.clone(),
                    its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint: Uint256::one().try_into().unwrap(),
                        max_decimals_when_truncating: 16u8
                    }
                }
            ));
        }
    }
}

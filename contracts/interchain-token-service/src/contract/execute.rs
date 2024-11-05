use axelar_wasm_std::{killswitch, nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage, Uint256};
use error_stack::{bail, ensure, report, Result, ResultExt};
use router_api::{Address, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::primitives::HubMessage;
use crate::state::{self, is_chain_frozen, load_config, load_its_contract, TokenDeploymentType};
use crate::{
    DeployInterchainToken, DeployTokenManager, InterchainTransfer, Message, TokenConfig, TokenId,
    TokenInstance,
};

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
    #[error("chain config for {0} already set")]
    ChainConfigAlreadySet(ChainNameRaw),
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
        expected: Option<u8>,
        actual: Option<u8>,
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
    let destination_address = load_its_contract(deps.storage, &destination_chain)
        .change_context_lazy(|| Error::UnknownChain(destination_chain.clone()))?;

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
    .add_event(
        Event::MessageReceived {
            cc_id,
            destination_chain,
            message,
        }
        .into(),
    ))
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
            apply_transfer(storage, source_chain, destination_chain, &transfer)
                .map(Message::InterchainTransfer)?
        }
        Message::DeployInterchainToken(deploy_token) => {
            apply_token_deployment(storage, &source_chain, &destination_chain, deploy_token)
                .map(Message::DeployInterchainToken)?
        }
        Message::DeployTokenManager(deploy_manager) => apply_token_manager_deployment(
            storage,
            &source_chain,
            &destination_chain,
            deploy_manager,
        )
        .map(Message::DeployTokenManager)?,
    }
    .then(Result::Ok)
}

fn ensure_chain_not_frozen(storage: &dyn Storage, chain: &ChainNameRaw) -> Result<(), Error> {
    ensure!(
        !is_chain_frozen(storage, chain).change_context(Error::State)?,
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
    destination_chain: &ChainNameRaw,
    destination_address: Address,
    payload: HexBinary,
) -> Result<Response, Error> {
    let config = load_config(storage);

    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(querier, &config.axelarnet_gateway).into();

    let call_contract_msg =
        gateway.call_contract(destination_chain.normalize(), destination_address, payload);

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

/// Calculates the destination on token transfer amount.
///
/// The amount is calculated based on the token decimals on the source and destination chains.
/// The calculation is done as following:
/// 1) `destination_amount` = `source_amount` * 10 ^ (`destination_chain_decimals` - `source_chain_decimals`)
/// 3) If `destination_amount` is greater than the destination chain's `max_uint`, the translation
/// fails.
/// 4) If `destination_amount` is zero, the translation fails.
fn destination_amount(
    storage: &dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
    token_id: TokenId,
    source_amount: nonempty::Uint256,
) -> Result<nonempty::Uint256, Error> {
    let source_token = try_load_token_instance(storage, source_chain.clone(), token_id)?;
    let destination_token = try_load_token_instance(storage, destination_chain.clone(), token_id)?;
    let (source_decimals, destination_decimals) =
        match (source_token.decimals, destination_token.decimals) {
            (Some(source_decimals), Some(destination_decimals))
                if source_decimals == destination_decimals =>
            {
                return Ok(source_amount)
            }
            (Some(source_decimals), Some(destination_decimals)) => {
                (source_decimals, destination_decimals)
            }
            (None, None) => return Ok(source_amount),
            _ => unreachable!(
                "decimals should be set in both the source and destination, or set in neither"
            ), // This should never happen
        };
    let destination_max_uint = state::load_chain_config(storage, destination_chain)
        .change_context(Error::State)?
        .max_uint;

    // It's intentionally written in this way since the end result may still be fine even if
    //     1) amount * (10 ^ (dest_chain_decimals)) overflows
    //     2) amount / (10 ^ (src_chain_decimals)) is zero
    let scaling_factor = Uint256::from_u128(10)
        .checked_pow(source_decimals.abs_diff(destination_decimals).into())
        .change_context_lazy(|| Error::InvalidTransferAmount {
            source_chain: source_chain.to_owned(),
            destination_chain: destination_chain.to_owned(),
            amount: source_amount,
        })?;
    let destination_amount = if source_decimals > destination_decimals {
        // Note: We should track the truncated dust in the global token config to allow recovery in the future
        // The token's decimals on the origin chain will always be greater than or equal to `source_decimals`, so we can scale and add to the total dust amount
        source_amount
            .checked_div(scaling_factor)
            .expect("scaling_factor must be non-zero")
    } else {
        source_amount
            .checked_mul(scaling_factor)
            .change_context_lazy(|| Error::InvalidTransferAmount {
                source_chain: source_chain.to_owned(),
                destination_chain: destination_chain.to_owned(),
                amount: source_amount,
            })?
    };

    // Note: Use ensure! instead of bail!?
    if destination_amount.gt(&destination_max_uint) {
        // Note: shall we different error enums to make debugging easier? Maybe add scaling factor in the error as well?
        bail!(Error::InvalidTransferAmount {
            source_chain: source_chain.to_owned(),
            destination_chain: destination_chain.to_owned(),
            amount: source_amount,
        })
    }

    nonempty::Uint256::try_from(destination_amount).change_context_lazy(|| {
        Error::InvalidTransferAmount {
            source_chain: source_chain.to_owned(),
            destination_chain: destination_chain.to_owned(),
            amount: source_amount,
        }
    })
}

/// Calculates the destination token decimals.
///
/// The destination chain's token decimals are calculated and saved as following:
/// 1) If the source chain's `max_uint` is less than or equal to the destination chain's `max_uint`,
///   the source chain's token decimals are used.
/// 2) Otherwise, the minimum of the source chain's token decimals and the source chain's
///  `max_target_decimals` is used.
fn destination_token_decimals(
    storage: &mut dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
    source_chain_decimals: u8,
) -> Result<u8, Error> {
    let source_chain_config =
        state::load_chain_config(storage, source_chain).change_context(Error::State)?;
    let destination_chain_config =
        state::load_chain_config(storage, destination_chain).change_context(Error::State)?;

    if source_chain_config
        .max_uint
        .le(&destination_chain_config.max_uint)
    {
        source_chain_decimals
    } else {
        // Note: Since destination_chain's `max_uint` is less than source_chain's, we need to use `max_target_decimals` of the destination chain.
        // E.g. Deploying token from Ethereum to Sui
        destination_chain_config
            .max_target_decimals
            .min(source_chain_decimals)
    }
    .then(Result::Ok)
}

fn apply_transfer(
    storage: &mut dyn Storage,
    source_chain: ChainNameRaw,
    destination_chain: ChainNameRaw,
    transfer: &InterchainTransfer,
) -> Result<InterchainTransfer, Error> {
    // Note: We're loading the token instances multiple times, are we refactoring it to load first and save at the end?
    // Same for chain config (checking frozen status and reading max_uint)
    let destination_amount = destination_amount(
        storage,
        &source_chain,
        &destination_chain,
        transfer.token_id,
        transfer.amount,
    )?;

    subtract_amount_from_source(storage, source_chain, transfer)?;

    let destination_transfer = InterchainTransfer {
        amount: destination_amount,

        ..transfer.clone()
    };
    add_amount_to_destination(storage, destination_chain, &destination_transfer)?;

    Ok(destination_transfer)
}

fn subtract_amount_from_source(
    storage: &mut dyn Storage,
    source_chain: ChainNameRaw,
    transfer: &InterchainTransfer,
) -> Result<(), Error> {
    let mut source_instance =
        try_load_token_instance(storage, source_chain.clone(), transfer.token_id)?;

    source_instance.supply = source_instance
        .supply
        .checked_sub(transfer.amount)
        .change_context_lazy(|| Error::TokenSupplyInvariantViolated {
            token_id: transfer.token_id,
            chain: source_chain.clone(),
        })?;

    state::save_token_instance(storage, source_chain, transfer.token_id, &source_instance)
        .change_context(Error::State)
}

fn add_amount_to_destination(
    storage: &mut dyn Storage,
    destination_chain: ChainNameRaw,
    transfer: &InterchainTransfer,
) -> Result<(), Error> {
    let mut destination_instance =
        try_load_token_instance(storage, destination_chain.clone(), transfer.token_id)?;

    destination_instance.supply = destination_instance
        .supply
        .checked_add(transfer.amount)
        .change_context_lazy(|| Error::TokenSupplyInvariantViolated {
            token_id: transfer.token_id,
            chain: destination_chain.clone(),
        })?;

    state::save_token_instance(
        storage,
        destination_chain,
        transfer.token_id,
        &destination_instance,
    )
    .change_context(Error::State)
}

fn apply_token_deployment(
    storage: &mut dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
    deploy_token: DeployInterchainToken,
) -> Result<DeployInterchainToken, Error> {
    let destination_token_decimals = destination_token_decimals(
        storage,
        source_chain,
        destination_chain,
        deploy_token.decimals,
    )?;

    save_token_instances(
        storage,
        source_chain,
        destination_chain,
        Some(deploy_token.decimals),
        Some(destination_token_decimals),
        deploy_token.token_id,
        &deploy_token.deployment_type(),
    )
    .map(|_| DeployInterchainToken {
        decimals: destination_token_decimals,

        ..deploy_token
    })
}

fn apply_token_manager_deployment(
    storage: &mut dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
    deploy_token_manager: DeployTokenManager,
) -> Result<DeployTokenManager, Error> {
    save_token_instances(
        storage,
        source_chain,
        destination_chain,
        None,
        None,
        deploy_token_manager.token_id,
        &deploy_token_manager.deployment_type(),
    )
    .map(|_| deploy_token_manager)
}

fn save_token_instances(
    storage: &mut dyn Storage,
    source_chain: &ChainNameRaw,
    destination_chain: &ChainNameRaw,
    source_token_decimals: Option<u8>,
    destination_token_decimals: Option<u8>,
    token_id: TokenId,
    deployment_type: &TokenDeploymentType,
) -> Result<(), Error> {
    ensure_token_not_deployed_on_destination(storage, token_id, destination_chain.clone())?;

    let token_config =
        state::may_load_token_config(storage, &token_id).change_context(Error::State)?;

    if let Some(TokenConfig { origin_chain, .. }) = token_config {
        ensure_matching_original_deployment(
            storage,
            origin_chain,
            source_chain,
            token_id,
            source_token_decimals,
        )?;
    } else {
        initialize_token_on_origin(storage, source_chain, token_id, source_token_decimals)?;
    }

    let destination_instance = TokenInstance::new(deployment_type, destination_token_decimals);

    state::save_token_instance(
        storage,
        destination_chain.clone(),
        token_id,
        &destination_instance,
    )
    .change_context(Error::State)
}

fn ensure_matching_original_deployment(
    storage: &dyn Storage,
    origin_chain: ChainNameRaw,
    source_chain: &ChainNameRaw,
    token_id: TokenId,
    source_token_decimals: Option<u8>,
) -> Result<(), Error> {
    ensure!(
        origin_chain == *source_chain,
        Error::TokenDeployedFromNonOriginChain {
            token_id,
            origin_chain: origin_chain.to_owned(),
            chain: source_chain.clone(),
        }
    );

    let token_instance = state::may_load_token_instance(storage, origin_chain.clone(), token_id)
        .change_context(Error::State)?
        .ok_or(report!(Error::TokenNotDeployed {
            token_id,
            chain: origin_chain.clone()
        }))?;
    ensure!(
        token_instance.decimals == source_token_decimals,
        Error::TokenDeployedDecimalsMismatch {
            token_id,
            chain: source_chain.clone(),
            expected: token_instance.decimals,
            actual: source_token_decimals
        }
    );

    Ok(())
}

fn try_load_token_instance(
    storage: &dyn Storage,
    chain: ChainNameRaw,
    token_id: TokenId,
) -> Result<TokenInstance, Error> {
    state::may_load_token_instance(storage, chain.clone(), token_id)
        .change_context(Error::State)?
        .ok_or(report!(Error::TokenNotDeployed { token_id, chain }))
}

fn initialize_token_on_origin(
    storage: &mut dyn Storage,
    source_chain: &ChainNameRaw,
    token_id: TokenId,
    decimals: Option<u8>,
) -> Result<(), Error> {
    // Token is being deployed for the first time
    let token_config = TokenConfig {
        origin_chain: source_chain.clone(),
    };
    let instance = TokenInstance::new_on_origin(decimals);

    state::save_token_config(storage, &token_id, &token_config)
        .and_then(|_| {
            state::save_token_instance(storage, source_chain.clone(), token_id, &instance)
        })
        .change_context(Error::State)?;
    Ok(())
}

/// Ensures that the token is not being redeployed to the same destination chain.
fn ensure_token_not_deployed_on_destination(
    storage: &dyn Storage,
    token_id: TokenId,
    destination_chain: ChainNameRaw,
) -> Result<(), Error> {
    let token_instance =
        state::may_load_token_instance(storage, destination_chain.clone(), token_id)
            .change_context(Error::State)?;

    ensure!(
        token_instance.is_none(),
        Error::TokenAlreadyDeployed {
            token_id,
            chain: destination_chain,
        }
    );

    Ok(())
}

trait DeploymentType {
    fn deployment_type(&self) -> TokenDeploymentType;
}

impl DeploymentType for DeployInterchainToken {
    fn deployment_type(&self) -> TokenDeploymentType {
        if self.minter.is_some() {
            TokenDeploymentType::CustomMinter
        } else {
            TokenDeploymentType::Trustless
        }
    }
}

impl DeploymentType for DeployTokenManager {
    fn deployment_type(&self) -> TokenDeploymentType {
        TokenDeploymentType::CustomMinter
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
    use crate::{DeployInterchainToken, HubMessage, InterchainTransfer};

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

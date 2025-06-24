use axelar_wasm_std::{killswitch, nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage, Uint256};
use error_stack::{bail, ensure, report, Result, ResultExt};
use interceptors::{deploy_token_to_destination_chain, deploy_token_to_source_chain};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::msg::SupplyModifier;
use crate::payload_translation::TranslationContract;
use crate::primitives::HubMessage;
use crate::state::{TokenConfig, TokenDeploymentType, TokenInstance, TokenSupply};
use crate::{
    msg, state, DeployInterchainToken, InterchainTransfer, LinkToken, Message,
    RegisterTokenMetadata, TokenId,
};

mod interceptors;

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
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
    #[error("chain {0} not registered")]
    ChainNotRegistered(ChainNameRaw),
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
    #[error("token {token_id} already registered with different origin chain {origin_chain}")]
    WrongOriginChain {
        token_id: TokenId,
        origin_chain: ChainNameRaw,
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
    #[error("token not registered {0}")]
    TokenNotRegistered(nonempty::HexBinary),
    #[error("attempted to register token {token_address} with {new_decimals} but already registered with {existing_decimals} decimals")]
    TokenDecimalsMismatch {
        token_address: nonempty::HexBinary,
        existing_decimals: u8,
        new_decimals: u8,
    },
    #[error("failed to query axelarnet gateway for chain name")]
    FailedToQueryAxelarnetGateway,
    #[error("supply modification overflowed. existing supply {0:?}")]
    ModifySupplyOverflow(TokenSupply),
    #[error("translation failed")]
    TranslationFailed,
}

///
/// This function handles the execution of ITS (Interchain Token Service) messages received from
/// its sources. It verifies the source address, decodes the message using translation hooks,
/// applies various checks and transformations, and forwards the message to the destination chain.
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

    // Use translation hook to decode the payload
    let hub_message =
        translate_from_bytes(deps.storage, deps.querier, &cc_id.source_chain, &payload)?;

    match hub_message {
        HubMessage::SendToHub {
            destination_chain,
            message,
        } => execute_message_on_hub(deps, cc_id, destination_chain, message),
        HubMessage::RegisterTokenMetadata(msg) => {
            execute_register_token_metadata(deps.storage, cc_id.source_chain, msg)
        }
        _ => bail!(Error::InvalidMessageType),
    }
}

fn axelar_chain_name(storage: &dyn Storage, querier: QuerierWrapper) -> Result<ChainName, Error> {
    let config = state::load_config(storage);
    let gateway: axelarnet_gateway::Client =
        client::ContractClient::new(querier, &config.axelarnet_gateway).into();
    gateway
        .chain_name()
        .change_context(Error::FailedToQueryAxelarnetGateway)
}

fn execute_message_on_hub(
    deps: DepsMut,
    cc_id: CrossChainId,
    destination_chain: ChainNameRaw,
    message: Message,
) -> Result<Response, Error> {
    let message = apply_to_hub(
        deps.storage,
        cc_id.source_chain.clone(),
        destination_chain.clone(),
        message,
    )?;

    let hub_message = HubMessage::ReceiveFromHub {
        source_chain: cc_id.source_chain.clone(),
        message: message.clone(),
    };

    // Use translation hook to encode the message for the destination chain
    let destination_payload =
        translate_to_bytes(deps.storage, deps.querier, &destination_chain, &hub_message)?;

    Ok(send_to_destination(
        deps.storage,
        deps.querier,
        &destination_chain,
        destination_payload,
    )?
    .add_event(Event::MessageReceived {
        cc_id,
        destination_chain,
        message,
    }))
}

/// Translate chain-specific payload to standardized ITS Hub Message format using translation contract
fn translate_from_bytes(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    source_chain: &ChainNameRaw,
    payload: &HexBinary,
) -> Result<HubMessage, Error> {
    let chain_config =
        state::load_chain_config(storage, source_chain).change_context(Error::State)?;

    let translation_client: TranslationContract<'_, cosmwasm_std::Empty> =
        TranslationContract::new(chain_config.translation_contract, querier);

    translation_client
        .from_bytes(payload.clone())
        .change_context(Error::InvalidPayload)
}

/// Translate standardized ITS Hub Message to chain-specific payload format using translation contract
fn translate_to_bytes(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: &ChainNameRaw,
    hub_message: &HubMessage,
) -> Result<HexBinary, Error> {
    let chain_config =
        state::load_chain_config(storage, destination_chain).change_context(Error::State)?;

    let translation_client: TranslationContract<'_, cosmwasm_std::Empty> =
        TranslationContract::new(chain_config.translation_contract, querier);

    translation_client
        .to_bytes(hub_message.clone())
        .change_context(Error::TranslationFailed)
}

fn execute_register_token_metadata(
    storage: &mut dyn Storage,
    source_chain: ChainNameRaw,
    register_token_metadata: RegisterTokenMetadata,
) -> Result<Response, Error> {
    ensure_chain_not_frozen(storage, &source_chain)?;

    interceptors::register_custom_token(
        storage,
        source_chain.clone(),
        register_token_metadata.clone(),
    )?;

    Ok(Response::new().add_event(Event::TokenMetadataRegistered {
        token_address: register_token_metadata.token_address,
        decimals: register_token_metadata.decimals,
        source_chain,
    }))
}

fn apply_to_link_token(
    storage: &mut dyn Storage,
    source_chain: ChainNameRaw,
    destination_chain: ChainNameRaw,
    link_token: LinkToken,
) -> Result<LinkToken, Error> {
    let source_token = state::may_load_custom_token(
        storage,
        source_chain.clone(),
        link_token.source_token_address.clone(),
    )
    .change_context(Error::State)?
    .ok_or(Error::TokenNotRegistered(
        link_token.source_token_address.clone(),
    ))?;

    deploy_token_to_source_chain(
        storage,
        &source_chain,
        link_token.token_id,
        source_token.decimals,
    )?;

    let destination_decimals = state::may_load_custom_token(
        storage,
        destination_chain.clone(),
        link_token.destination_token_address.clone(),
    )
    .change_context(Error::State)?
    .ok_or(Error::TokenNotRegistered(
        link_token.destination_token_address.clone(),
    ))?
    .decimals;

    deploy_token_to_destination_chain(
        storage,
        &destination_chain,
        link_token.token_id,
        destination_decimals,
        TokenDeploymentType::CustomMinter,
    )?;

    Ok(link_token)
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
    interceptors::deploy_token_to_source_chain(
        storage,
        source_chain,
        deploy_token.token_id,
        deploy_token.decimals,
    )?;
    let deploy_token = interceptors::calculate_scaling_factor(
        storage,
        source_chain,
        destination_chain,
        deploy_token,
    )?;
    interceptors::deploy_token_to_destination_chain(
        storage,
        destination_chain,
        deploy_token.token_id,
        deploy_token.decimals,
        deploy_token.deployment_type(),
    )?;

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
    let source_its_contract =
        state::load_its_contract(storage, source_chain).change_context(Error::State)?;

    ensure!(
        source_address == &source_its_contract,
        Error::UnknownItsContract(source_address.clone())
    );

    Ok(())
}

fn ensure_chain_is_registered(storage: &dyn Storage, chain: ChainNameRaw) -> Result<(), Error> {
    ensure!(
        state::may_load_chain_config(storage, &chain)
            .change_context(Error::State)?
            .is_some(),
        Error::ChainNotRegistered(chain)
    );

    Ok(())
}

fn send_to_destination(
    storage: &dyn Storage,
    querier: QuerierWrapper,
    destination_chain: &ChainNameRaw,
    payload: HexBinary,
) -> Result<Response, Error> {
    if *destination_chain == axelar_chain_name(storage, querier)? {
        // right now, messages sent to the axelar chain are not forwarded on to
        // any other contract (in contrast to every other message that moves through the hub)
        // In the future, this may change, depending on the message type
        // The main use case for this at the moment is the RegisterToken message,
        // which simply informs the ITS hub of the decimals and token address of a
        // custom token, and thus needs no forwarding.
        return Ok(Response::new());
    }

    let destination_address = state::load_its_contract(storage, destination_chain)
        .change_context_lazy(|| Error::ChainNotRegistered(destination_chain.clone()))?;

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

pub fn register_chains(
    mut deps: DepsMut,
    chains: Vec<msg::ChainConfig>,
) -> Result<Response, Error> {
    chains
        .into_iter()
        .try_for_each(|chain_config| register_chain(&mut deps, chain_config))?;

    Ok(Response::new())
}

fn register_chain(deps: &mut DepsMut, config: msg::ChainConfig) -> Result<(), Error> {
    let chain = config.chain.clone();
    let validated_config =
        state::ChainConfig::from_input(config, deps.api).change_context(Error::State)?;
    match state::may_load_chain_config(deps.storage, &chain).change_context(Error::State)? {
        Some(_) => bail!(Error::ChainAlreadyRegistered(chain)),
        None => state::save_chain_config(deps.storage, &chain, &validated_config)
            .change_context(Error::State)?,
    };
    Ok(())
}

pub fn update_chains(mut deps: DepsMut, chains: Vec<msg::ChainConfig>) -> Result<Response, Error> {
    chains
        .into_iter()
        .try_for_each(|chain_config| update_chain(&mut deps, chain_config))?;

    Ok(Response::new())
}

fn update_chain(deps: &mut DepsMut, config: msg::ChainConfig) -> Result<(), Error> {
    let chain = config.chain.clone();
    let validated_config =
        state::ChainConfig::from_input(config, deps.api).change_context(Error::State)?;
    match state::may_load_chain_config(deps.storage, &chain).change_context(Error::State)? {
        None => bail!(Error::ChainNotRegistered(chain)),
        Some(_) => state::save_chain_config(deps.storage, &chain, &validated_config)
            .change_context(Error::State)?,
    };
    Ok(())
}

pub fn modify_supply(
    deps: DepsMut,
    chain: ChainNameRaw,
    token_id: TokenId,
    supply_modifier: SupplyModifier,
) -> Result<Response, Error> {
    let mut token_instance = state::may_load_token_instance(deps.storage, chain.clone(), token_id)
        .change_context(Error::State)?
        .ok_or(Error::TokenNotDeployed {
            token_id,
            chain: chain.clone(),
        })?;

    // set supply to tracked if untracked
    if token_instance.supply == TokenSupply::Untracked {
        token_instance.supply = TokenSupply::Tracked(Uint256::zero());
    }

    token_instance.supply = match supply_modifier {
        SupplyModifier::IncreaseSupply(amount) => token_instance
            .supply
            .clone()
            .checked_add(amount)
            .change_context(Error::ModifySupplyOverflow(token_instance.supply))?,
        SupplyModifier::DecreaseSupply(amount) => token_instance
            .supply
            .clone()
            .checked_sub(amount)
            .change_context(Error::ModifySupplyOverflow(token_instance.supply))?,
    };

    state::save_token_instance(deps.storage, chain.clone(), token_id, &token_instance)
        .change_context(Error::State)?;

    Ok(Response::new().add_event(Event::SupplyModified {
        token_id,
        chain,
        supply_modifier,
    }))
}

pub fn register_p2p_token_instance(
    deps: DepsMut,
    token_id: TokenId,
    chain: ChainNameRaw,
    origin_chain: ChainNameRaw,
    decimals: u8,
    supply: msg::TokenSupply,
) -> Result<Response, Error> {
    let supply: TokenSupply = supply.into();

    ensure_chain_is_registered(deps.storage, chain.clone())?;
    ensure_chain_is_registered(deps.storage, origin_chain.clone())?;

    match state::may_load_token_config(deps.storage, &token_id).change_context(Error::State)? {
        Some(TokenConfig {
            origin_chain: stored_origin_chain,
        }) => {
            // Each token has a single global config, which is set the first time the token is deployed
            // Subsequent deployments should not modify the existing config
            // However, if a config exists, we need to check that the origin chain matches
            ensure!(
                stored_origin_chain == origin_chain,
                Error::WrongOriginChain {
                    token_id,
                    origin_chain: stored_origin_chain
                }
            );
        }
        None => state::save_token_config(deps.storage, token_id, &TokenConfig { origin_chain })
            .change_context(Error::State)?,
    }

    if state::may_load_token_instance(deps.storage, chain.clone(), token_id)
        .change_context(Error::State)?
        .is_some()
    {
        bail!(Error::TokenAlreadyDeployed { token_id, chain });
    }

    state::save_token_instance(
        deps.storage,
        chain.clone(),
        token_id,
        &TokenInstance { supply, decimals },
    )
    .change_context(Error::State)?;

    Ok(Response::new())
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
        Message::LinkToken(link_token) => {
            apply_to_link_token(storage, source_chain, destination_chain, link_token)
                .map(Message::LinkToken)?
        }
    }
    .then(Result::Ok)
}

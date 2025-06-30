use axelar_wasm_std::{killswitch, nonempty, FnExt, IntoContractError};
use cosmwasm_std::{DepsMut, HexBinary, QuerierWrapper, Response, Storage, Uint256};
use error_stack::{bail, ensure, report, Result, ResultExt};
use interceptors::{deploy_token_to_destination_chain, deploy_token_to_source_chain};
use interchain_token_api::payload_translation::Client as TranslationClient;
use interchain_token_api::{
    DeployInterchainToken, HubMessage, InterchainTransfer, LinkToken, Message,
    RegisterTokenMetadata, TokenId,
};
use router_api::{Address, ChainName, ChainNameRaw, CrossChainId};

use crate::events::Event;
use crate::msg::SupplyModifier;
use crate::state::{TokenConfig, TokenDeploymentType, TokenInstance, TokenSupply};
use crate::{msg, state};

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

    let translation_client: TranslationClient =
        client::ContractClient::new(querier, &chain_config.translation_contract).into();

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

    let translation_client: TranslationClient =
        client::ContractClient::new(querier, &chain_config.translation_contract).into();

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

#[cfg(test)]
mod tests {

    use abi_translation_contract::abi::hub_message_abi_encode;
    use assert_ok::assert_ok;
    use axelar_wasm_std::msg_id::HexTxHashAndEventIndex;
    use axelar_wasm_std::{assert_err_contains, killswitch, nonempty, permission_control};
    use axelarnet_gateway::msg::QueryMsg;
    use cosmwasm_std::testing::{mock_dependencies, MockApi, MockQuerier};
    use cosmwasm_std::{
        from_json, to_json_binary, DepsMut, HexBinary, MemoryStorage, OwnedDeps, Response, Uint256,
        WasmQuery,
    };
    use error_stack::{report, Result};
    use interchain_token_api::payload_translation::Client as TranslationClient;
    use interchain_token_api::{
        DeployInterchainToken, HubMessage, InterchainTransfer, LinkToken, Message,
        RegisterTokenMetadata, TokenId,
    };
    use router_api::{ChainName, ChainNameRaw, CrossChainId};

    use super::{apply_to_hub, register_p2p_token_instance};
    use crate::contract::execute::{
        apply_to_transfer, disable_execution, enable_execution, execute_message, freeze_chain,
        modify_supply, register_chain, register_chains, unfreeze_chain, update_chains, Error,
    };
    use crate::msg;
    use crate::msg::TruncationConfig;
    use crate::state::{self, Config, TokenSupply};

    const SOLANA: &str = "solana";
    const ETHEREUM: &str = "ethereum";
    const XRPL: &str = "xrpl";
    const AXELAR: &str = "axelar";

    const ITS_ADDRESS: &str = "68d30f47F19c07bCCEf4Ac7FAE2Dc12FCa3e0dC9";

    const ADMIN: &str = "admin";
    const GOVERNANCE: &str = "governance";
    const AXELARNET_GATEWAY: &str = "axelarnet-gateway";

    #[test]
    fn should_be_able_to_transfer() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        assert_ok!(deploy_token(
            deps.as_mut(),
            ethereum(),
            solana(),
            token_id()
        ));

        assert_ok!(transfer_token(
            deps.as_mut(),
            ethereum(),
            solana(),
            token_id(),
            Uint256::one().try_into().unwrap()
        ));
    }

    #[test]
    fn should_not_be_able_to_transfer_more_than_supply() {
        let mut deps = mock_dependencies();
        init(&mut deps);
        let origin_chain = ethereum();
        let remote_chain = solana();

        assert_ok!(deploy_token(
            deps.as_mut(),
            origin_chain.clone(),
            remote_chain.clone(),
            token_id()
        ));

        let starting_supply =
            assert_ok!(get_supply(deps.as_mut(), remote_chain.clone(), token_id()));
        assert_eq!(starting_supply, TokenSupply::Tracked(Uint256::zero()));

        // we try to transfer from the remote chain to the origin chain, which should fail
        // since the token was just deployed and thus there is no supply on remote chain yet
        assert_err_contains!(
            transfer_token(
                deps.as_mut(),
                remote_chain,
                origin_chain,
                token_id(),
                Uint256::one().try_into().unwrap()
            ),
            Error,
            Error::TokenSupplyInvariantViolated { .. }
        );
    }

    #[test]
    fn should_be_able_to_increase_supply() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        assert_ok!(deploy_token(
            deps.as_mut(),
            ethereum(),
            solana(),
            token_id()
        ));

        let starting_supply = assert_ok!(get_supply(deps.as_mut(), solana(), token_id()));
        assert_eq!(starting_supply, TokenSupply::Tracked(Uint256::zero()));

        let supply_increase = Uint256::from_u128(100).try_into().unwrap();
        assert_ok!(modify_supply(
            deps.as_mut(),
            solana(),
            token_id(),
            msg::SupplyModifier::IncreaseSupply(supply_increase)
        ));

        let expected_supply = assert_ok!(starting_supply.checked_add(supply_increase));
        let result_supply = assert_ok!(get_supply(deps.as_mut(), solana(), token_id()));

        assert_eq!(result_supply, expected_supply);

        // transfer from solana to ethereum should succeed, since we manually set the supply
        // otherwise this would fail, since there have been no transfers to solana and thus no supply
        assert_ok!(transfer_token(
            deps.as_mut(),
            solana(),
            ethereum(),
            token_id(),
            Uint256::one().try_into().unwrap()
        ));
    }

    #[test]
    fn should_be_able_to_decrease_supply() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        assert_ok!(deploy_token(
            deps.as_mut(),
            ethereum(),
            solana(),
            token_id()
        ));

        // perform a transfer to add some token supply to solana
        let initial_transfer = Uint256::from_u128(100).try_into().unwrap();
        assert_ok!(transfer_token(
            deps.as_mut(),
            ethereum(),
            solana(),
            token_id(),
            initial_transfer
        ));

        let current_supply = assert_ok!(get_supply(deps.as_mut(), solana(), token_id()));
        assert_eq!(current_supply, TokenSupply::Tracked(*initial_transfer));

        let supply_decrease = initial_transfer;
        assert_ok!(modify_supply(
            deps.as_mut(),
            solana(),
            token_id(),
            msg::SupplyModifier::DecreaseSupply(supply_decrease)
        ));

        let expected_supply = assert_ok!(current_supply.checked_sub(supply_decrease));
        let result_supply = assert_ok!(get_supply(deps.as_mut(), solana(), token_id()));
        assert_eq!(result_supply, expected_supply);

        // transfer from solana to ethereum should fail. We transferred 100 tokens to solana at the start of the test,
        // but then manually decreased the supply, so there should not be 100 tokens to transfer from solana
        assert_err_contains!(
            transfer_token(
                deps.as_mut(),
                solana(),
                ethereum(),
                token_id(),
                initial_transfer
            ),
            Error,
            Error::TokenSupplyInvariantViolated { .. }
        );
    }

    #[test]
    fn should_be_able_to_set_supply_on_untracked() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        assert_ok!(deploy_token_custom_minter(
            deps.as_mut(),
            ethereum(),
            solana(),
            token_id(),
            its_address()
        ));

        let supply_increase = Uint256::from_u128(50);
        let expected_supply = TokenSupply::Tracked(supply_increase);
        assert_ok!(modify_supply(
            deps.as_mut(),
            solana(),
            token_id(),
            msg::SupplyModifier::IncreaseSupply(supply_increase.try_into().unwrap())
        ));

        let result_supply = assert_ok!(get_supply(deps.as_mut(), solana(), token_id()));
        assert_eq!(result_supply, expected_supply);

        // try to transfer more than the supply we just set, should fail
        assert_err_contains!(
            transfer_token(
                deps.as_mut(),
                solana(),
                ethereum(),
                token_id(),
                supply_increase
                    .checked_add(Uint256::one())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
            Error,
            Error::TokenSupplyInvariantViolated { .. }
        );
    }

    #[test]
    fn should_not_be_able_to_set_supply_on_not_deployed_token() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        assert_err_contains!(
            modify_supply(
                deps.as_mut(),
                solana(),
                token_id(),
                msg::SupplyModifier::IncreaseSupply(Uint256::from_u128(50u128).try_into().unwrap())
            ),
            Error,
            Error::TokenNotDeployed { .. }
        );

        // deploy the token
        assert_ok!(deploy_token(
            deps.as_mut(),
            ethereum(),
            solana(),
            token_id()
        ));

        // token id exists now, but try to modify supply on a chain where it is not yet deployed
        assert_err_contains!(
            modify_supply(
                deps.as_mut(),
                ChainNameRaw::try_from(XRPL).unwrap(),
                token_id(),
                msg::SupplyModifier::IncreaseSupply(Uint256::from_u128(50u128).try_into().unwrap())
            ),
            Error,
            Error::TokenNotDeployed { .. }
        );
    }

    #[test]
    fn modify_supply_should_detect_overflow_underflow() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        assert_ok!(deploy_token(
            deps.as_mut(),
            ethereum(),
            solana(),
            token_id()
        ));

        assert_ok!(modify_supply(
            deps.as_mut(),
            solana(),
            token_id(),
            msg::SupplyModifier::IncreaseSupply(Uint256::one().try_into().unwrap())
        ));

        assert_err_contains!(
            modify_supply(
                deps.as_mut(),
                solana(),
                token_id(),
                msg::SupplyModifier::IncreaseSupply(Uint256::MAX.try_into().unwrap())
            ),
            Error,
            Error::ModifySupplyOverflow { .. }
        );

        assert_err_contains!(
            modify_supply(
                deps.as_mut(),
                solana(),
                token_id(),
                msg::SupplyModifier::DecreaseSupply(Uint256::MAX.try_into().unwrap())
            ),
            Error,
            Error::ModifySupplyOverflow { .. }
        );
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
            hub_message_abi_encode(msg.clone()),
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
            hub_message_abi_encode(msg.clone()),
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
            hub_message_abi_encode(msg),
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
            hub_message_abi_encode(msg.clone()),
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
            hub_message_abi_encode(msg.clone()),
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
            hub_message_abi_encode(msg.clone()),
        );
        assert_err_contains!(res, Error, Error::ChainFrozen(..));

        assert_ok!(unfreeze_chain(deps.as_mut(), destination_chain));

        assert_ok!(execute_message(
            deps.as_mut(),
            cc_id,
            ITS_ADDRESS.to_string().try_into().unwrap(),
            hub_message_abi_encode(msg),
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
            hub_message_abi_encode(msg.clone()),
        ));
    }

    #[test]
    fn register_chain_fails_if_already_registered() {
        let mut deps = mock_dependencies();
        assert_ok!(register_chain(
            &mut deps.as_mut(),
            msg::ChainConfig {
                chain: SOLANA.parse().unwrap(),
                its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                truncation: TruncationConfig {
                    max_uint_bits: 256.try_into().unwrap(),
                    max_decimals_when_truncating: 16u8
                },
                translation_contract: MockApi::default()
                    .addr_make("translation")
                    .to_string()
                    .try_into()
                    .unwrap(),
            }
        ));
        assert_err_contains!(
            register_chain(
                &mut deps.as_mut(),
                msg::ChainConfig {
                    chain: SOLANA.parse().unwrap(),
                    its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 256.try_into().unwrap(),
                        max_decimals_when_truncating: 16u8
                    },
                    translation_contract: MockApi::default()
                        .addr_make("translation")
                        .to_string()
                        .try_into()
                        .unwrap(),
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
                    max_uint_bits: 256.try_into().unwrap(),
                    max_decimals_when_truncating: 16u8,
                },
                translation_contract: MockApi::default()
                    .addr_make("translation")
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            msg::ChainConfig {
                chain: XRPL.parse().unwrap(),
                its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                truncation: TruncationConfig {
                    max_uint_bits: 256.try_into().unwrap(),
                    max_decimals_when_truncating: 16u8,
                },
                translation_contract: MockApi::default()
                    .addr_make("translation")
                    .to_string()
                    .try_into()
                    .unwrap(),
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
    fn update_chains_fails_if_not_registered() {
        let mut deps = mock_dependencies();
        assert_err_contains!(
            update_chains(
                deps.as_mut(),
                vec![msg::ChainConfig {
                    chain: SOLANA.parse().unwrap(),
                    its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 256.try_into().unwrap(),
                        max_decimals_when_truncating: 16u8,
                    },
                    translation_contract: MockApi::default()
                        .addr_make("translation")
                        .to_string()
                        .try_into()
                        .unwrap(),
                }]
            ),
            Error,
            Error::ChainNotRegistered(..)
        );
    }

    #[test]
    fn update_max_uint_and_decimals_should_affect_new_tokens() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let token_id: TokenId = [7u8; 32].into();
        let solana = ChainNameRaw::try_from(SOLANA).unwrap();
        let ethereum = ChainNameRaw::try_from(ETHEREUM).unwrap();

        // update the max_uint to u128 max (previously was u256 max) and reduce decimals when truncating to 6
        let new_decimals = 6u8;
        assert_ok!(update_chains(
            deps.as_mut(),
            vec![msg::ChainConfig {
                chain: solana.clone(),
                its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                truncation: TruncationConfig {
                    max_uint_bits: 128.try_into().unwrap(),
                    max_decimals_when_truncating: new_decimals,
                },
                translation_contract: MockApi::default()
                    .addr_make("translation")
                    .to_string()
                    .try_into()
                    .unwrap(),
            }]
        ));

        // now deploy a token with 18 decimals. Should truncate to 6
        let msg = HubMessage::SendToHub {
            destination_chain: solana.clone(),
            message: DeployInterchainToken {
                token_id,
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            }
            .into(),
        };
        let cc_id = CrossChainId {
            source_chain: ethereum.clone(),
            message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32).into(),
        };

        assert_ok!(execute_message(
            deps.as_mut(),
            cc_id.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
            hub_message_abi_encode(msg.clone()),
        ));

        // destination token instance should use 6 decimals
        let destination_token_instance = assert_ok!(state::may_load_token_instance(
            deps.as_mut().storage,
            solana.clone(),
            token_id,
        ));
        assert!(destination_token_instance.is_some());
        assert_eq!(destination_token_instance.unwrap().decimals, new_decimals);

        // source instance should use 18
        let source_token_instance = assert_ok!(state::may_load_token_instance(
            deps.as_mut().storage,
            ethereum.clone(),
            token_id,
        ));
        assert!(source_token_instance.is_some());
        assert_eq!(source_token_instance.unwrap().decimals, 18u8);

        // transfers should be scaled appropriately
        let transfer = InterchainTransfer {
            token_id,
            amount: Uint256::from_u128(1000000000000).try_into().unwrap(),
            source_address: its_address(),
            destination_address: its_address(),
            data: None,
        };
        let transformed_transfer = assert_ok!(apply_to_transfer(
            deps.as_mut().storage,
            ethereum,
            solana,
            transfer.clone(),
        ));
        assert_eq!(
            transformed_transfer.amount,
            Uint256::one().try_into().unwrap()
        );
    }

    #[test]
    fn update_max_uint_and_decimals_should_not_affect_existing_tokens() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let token_id: TokenId = [7u8; 32].into();
        let solana = ChainNameRaw::try_from(SOLANA).unwrap();
        let ethereum = ChainNameRaw::try_from(ETHEREUM).unwrap();

        // deploy a token with 18 decimals
        let msg = HubMessage::SendToHub {
            destination_chain: solana.clone(),
            message: DeployInterchainToken {
                token_id,
                name: "Test".parse().unwrap(),
                symbol: "TEST".parse().unwrap(),
                decimals: 18,
                minter: None,
            }
            .into(),
        };
        let cc_id = CrossChainId {
            source_chain: ethereum.clone(),
            message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32).into(),
        };

        assert_ok!(execute_message(
            deps.as_mut(),
            cc_id.clone(),
            ITS_ADDRESS.to_string().try_into().unwrap(),
            hub_message_abi_encode(msg.clone()),
        ));

        // update the max_uint to u128 max (previously was u256 max) and reduce decimals when truncating to 6
        assert_ok!(update_chains(
            deps.as_mut(),
            vec![msg::ChainConfig {
                chain: solana.clone(),
                its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                truncation: TruncationConfig {
                    max_uint_bits: 128.try_into().unwrap(),
                    max_decimals_when_truncating: 6u8,
                },
                translation_contract: MockApi::default()
                    .addr_make("translation")
                    .to_string()
                    .try_into()
                    .unwrap(),
            }]
        ));

        // previously deployed tokens should have 18 decimals, unaffected by the config update
        let destination_token_instance = assert_ok!(state::may_load_token_instance(
            deps.as_mut().storage,
            solana.clone(),
            token_id
        ));
        assert!(destination_token_instance.is_some());
        assert_eq!(destination_token_instance.unwrap().decimals, 18u8);

        let source_token_instance = assert_ok!(state::may_load_token_instance(
            deps.as_mut().storage,
            ethereum.clone(),
            token_id
        ));
        assert!(source_token_instance.is_some());
        assert_eq!(source_token_instance.unwrap().decimals, 18u8);

        // transfers should not be scaled, since decimals are the same
        let transfer = InterchainTransfer {
            token_id,
            amount: Uint256::from_u128(1000000000000).try_into().unwrap(),
            source_address: its_address(),
            destination_address: its_address(),
            data: None,
        };
        let transformed_transfer = assert_ok!(apply_to_transfer(
            deps.as_mut().storage,
            ethereum,
            solana,
            transfer.clone(),
        ));
        assert_eq!(transformed_transfer.amount, transfer.amount);
    }

    #[test]
    fn should_link_custom_tokens_with_different_decimals() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let source_chain = ChainNameRaw::try_from(SOLANA).unwrap();
        let destination_chain = ChainNameRaw::try_from(ETHEREUM).unwrap();
        let source_decimals = 12u8;
        let destination_decimals = 6u8;
        let token_address: nonempty::HexBinary =
            HexBinary::from_hex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                .unwrap()
                .try_into()
                .unwrap();
        let token_id = TokenId::new([1; 32]);
        register_and_link_custom_tokens(
            &mut deps,
            token_id,
            source_chain.clone(),
            destination_chain.clone(),
            source_decimals,
            destination_decimals,
            token_address.clone(),
        );

        let transfer_amount = Uint256::from_u128(100000000u128);
        let msg = Message::InterchainTransfer(InterchainTransfer {
            token_id,
            source_address: token_address.clone(),
            destination_address: token_address.clone(),
            data: None,
            amount: transfer_amount.try_into().unwrap(),
        });

        let res = assert_ok!(apply_to_hub(
            deps.as_mut().storage,
            source_chain.clone(),
            destination_chain.clone(),
            msg.clone()
        ));

        let scaling_factor = Uint256::from_u128(10)
            .checked_pow(source_decimals.abs_diff(destination_decimals).into())
            .unwrap();

        let transfer = get_transfer(res);

        assert_eq!(
            Uint256::from(transfer.amount),
            transfer_amount.checked_div(scaling_factor).unwrap()
        );

        // check the other direction
        let res = assert_ok!(apply_to_hub(
            deps.as_mut().storage,
            destination_chain,
            source_chain,
            msg
        ));

        let transfer = get_transfer(res);

        assert_eq!(
            Uint256::from(transfer.amount),
            transfer_amount.checked_mul(scaling_factor).unwrap()
        );
    }

    #[test]
    fn should_link_custom_tokens_with_same_decimals() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let source_chain = ChainNameRaw::try_from(SOLANA).unwrap();
        let destination_chain = ChainNameRaw::try_from(ETHEREUM).unwrap();
        let source_decimals = 12u8;
        let destination_decimals = 12u8;
        let token_address: nonempty::HexBinary =
            HexBinary::from_hex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                .unwrap()
                .try_into()
                .unwrap();
        let token_id = TokenId::new([1; 32]);
        register_and_link_custom_tokens(
            &mut deps,
            token_id,
            source_chain.clone(),
            destination_chain.clone(),
            source_decimals,
            destination_decimals,
            token_address.clone(),
        );

        let transfer_amount = Uint256::from_u128(100000000u128);
        let msg = Message::InterchainTransfer(InterchainTransfer {
            token_id,
            source_address: token_address.clone(),
            destination_address: token_address.clone(),
            data: None,
            amount: transfer_amount.try_into().unwrap(),
        });

        let res = assert_ok!(apply_to_hub(
            deps.as_mut().storage,
            source_chain.clone(),
            destination_chain.clone(),
            msg.clone()
        ));

        let transfer = get_transfer(res);

        assert_eq!(Uint256::from(transfer.amount), transfer_amount,);

        // check the other direction
        let res = assert_ok!(apply_to_hub(
            deps.as_mut().storage,
            destination_chain,
            source_chain,
            msg
        ));

        let transfer = get_transfer(res);

        assert_eq!(Uint256::from(transfer.amount), transfer_amount,);
    }

    fn get_transfer(message: Message) -> InterchainTransfer {
        match message {
            Message::InterchainTransfer(transfer) => transfer,
            _ => panic!("wrong msg type returned"),
        }
    }

    #[test]
    fn should_fail_to_link_tokens_if_not_registered_on_source() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let source_chain = ChainNameRaw::try_from(SOLANA).unwrap();
        let destination_chain = ChainNameRaw::try_from(ETHEREUM).unwrap();
        let token_address: nonempty::HexBinary =
            HexBinary::from_hex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                .unwrap()
                .try_into()
                .unwrap();
        let token_id = TokenId::new([1; 32]);
        register_custom_token(
            &mut deps,
            destination_chain.clone(),
            10u8,
            token_address.clone(),
        );

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: LinkToken {
                token_id,
                token_manager_type: Uint256::zero(),
                source_token_address: token_address.clone(),
                destination_token_address: token_address.clone(),
                params: None,
            }
            .into(),
        };

        assert_err_contains!(
            execute_message(
                deps.as_mut(),
                CrossChainId {
                    source_chain: source_chain.clone(),
                    message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                        .to_string()
                        .try_into()
                        .unwrap(),
                },
                ITS_ADDRESS.to_string().try_into().unwrap(),
                hub_message_abi_encode(msg.clone()),
            ),
            Error,
            Error::TokenNotRegistered(..)
        );
    }

    #[test]
    fn should_fail_to_link_tokens_if_not_registered_on_destination() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let source_chain = ChainNameRaw::try_from(SOLANA).unwrap();
        let destination_chain = ChainNameRaw::try_from(ETHEREUM).unwrap();
        let token_address: nonempty::HexBinary =
            HexBinary::from_hex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                .unwrap()
                .try_into()
                .unwrap();
        let token_id = TokenId::new([1; 32]);
        register_custom_token(&mut deps, source_chain.clone(), 10u8, token_address.clone());

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: LinkToken {
                token_id,
                token_manager_type: Uint256::zero(),
                source_token_address: token_address.clone(),
                destination_token_address: token_address.clone(),
                params: None,
            }
            .into(),
        };

        assert_err_contains!(
            execute_message(
                deps.as_mut(),
                CrossChainId {
                    source_chain: source_chain.clone(),
                    message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                        .to_string()
                        .try_into()
                        .unwrap(),
                },
                ITS_ADDRESS.to_string().try_into().unwrap(),
                hub_message_abi_encode(msg.clone()),
            ),
            Error,
            Error::TokenNotRegistered(..)
        );
    }

    #[test]
    fn should_fail_to_link_tokens_if_not_registered_on_source_or_destination() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let source_chain = ChainNameRaw::try_from(SOLANA).unwrap();
        let destination_chain = ChainNameRaw::try_from(ETHEREUM).unwrap();
        let token_address: nonempty::HexBinary =
            HexBinary::from_hex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                .unwrap()
                .try_into()
                .unwrap();
        let token_id = TokenId::new([1; 32]);

        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: LinkToken {
                token_id,
                token_manager_type: Uint256::zero(),
                source_token_address: token_address.clone(),
                destination_token_address: token_address.clone(),
                params: None,
            }
            .into(),
        };

        assert_err_contains!(
            execute_message(
                deps.as_mut(),
                CrossChainId {
                    source_chain: source_chain.clone(),
                    message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                        .to_string()
                        .try_into()
                        .unwrap(),
                },
                ITS_ADDRESS.to_string().try_into().unwrap(),
                hub_message_abi_encode(msg.clone()),
            ),
            Error,
            Error::TokenNotRegistered(..)
        );
    }

    #[test]
    fn should_modify_supply_on_custom_tokens() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        register_and_link_custom_tokens(
            &mut deps,
            token_id(),
            ethereum(),
            solana(),
            18,
            18,
            its_address(),
        );

        assert_ok!(modify_supply(
            deps.as_mut(),
            solana(),
            token_id(),
            msg::SupplyModifier::IncreaseSupply(Uint256::from_u128(50u128).try_into().unwrap())
        ));

        assert_err_contains!(
            transfer_token(
                deps.as_mut(),
                solana(),
                ethereum(),
                token_id(),
                Uint256::from_u128(100u128).try_into().unwrap()
            ),
            Error,
            Error::TokenSupplyInvariantViolated { .. }
        );

        // a smaller transfer should succeed
        assert_ok!(transfer_token(
            deps.as_mut(),
            solana(),
            ethereum(),
            token_id(),
            Uint256::from_u128(50u128).try_into().unwrap()
        ));
    }

    #[test]
    fn should_register_p2p_tokens() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let origin_chain = ethereum();
        let instance_chains: Vec<ChainNameRaw> = vec![solana(), ethereum()];
        let decimals = 18;
        let supply = msg::TokenSupply::Tracked(Uint256::one());

        for chain in instance_chains {
            assert_ok!(register_p2p_token_instance(
                deps.as_mut(),
                token_id(),
                chain,
                origin_chain.clone(),
                decimals,
                supply.clone()
            ));
        }

        assert_ok!(transfer_token(
            deps.as_mut(),
            ethereum(),
            solana(),
            token_id(),
            Uint256::one().try_into().unwrap()
        ));
    }

    #[test]
    fn should_transfer_between_p2p_tokens_and_hub_deployed_tokens() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        // deploy to solana via the hub
        assert_ok!(deploy_token(
            deps.as_mut(),
            ethereum(),
            solana(),
            token_id()
        ));

        // register instance of same token deployed on xrpl
        assert_ok!(register_p2p_token_instance(
            deps.as_mut(),
            token_id(),
            xrpl(),
            ethereum(),
            18,
            msg::TokenSupply::Tracked(Uint256::one())
        ));

        // test transfer in both directions
        assert_ok!(transfer_token(
            deps.as_mut(),
            xrpl(),
            solana(),
            token_id(),
            Uint256::one().try_into().unwrap()
        ));

        assert_ok!(transfer_token(
            deps.as_mut(),
            solana(),
            xrpl(),
            token_id(),
            Uint256::one().try_into().unwrap()
        ));
    }

    #[test]
    fn should_not_register_same_p2p_token_twice() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let decimals = 18;
        let supply = msg::TokenSupply::Tracked(Uint256::one());
        assert_ok!(register_p2p_token_instance(
            deps.as_mut(),
            token_id(),
            solana(),
            ethereum(),
            decimals,
            supply.clone()
        ));
        let res = register_p2p_token_instance(
            deps.as_mut(),
            token_id(),
            solana(),
            ethereum(),
            decimals,
            supply.clone(),
        );
        assert_err_contains!(res, Error, Error::TokenAlreadyDeployed { .. });
    }

    #[test]
    fn should_not_register_p2p_token_with_different_origin() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let origin_chain = ethereum();
        let instance_chain = solana();
        let decimals = 18;
        let supply = msg::TokenSupply::Tracked(Uint256::one());
        assert_ok!(register_p2p_token_instance(
            deps.as_mut(),
            token_id(),
            origin_chain.clone(),
            origin_chain.clone(),
            decimals,
            supply.clone()
        ));
        let wrong_origin_chain = xrpl();
        let res = register_p2p_token_instance(
            deps.as_mut(),
            token_id(),
            instance_chain,
            wrong_origin_chain,
            decimals,
            supply.clone(),
        );
        assert_err_contains!(res, Error, Error::WrongOriginChain { .. });
    }

    #[test]
    fn should_not_register_p2p_token_with_unregistered_chain() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let decimals = 18;
        let supply = msg::TokenSupply::Tracked(Uint256::one());
        assert_err_contains!(
            register_p2p_token_instance(
                deps.as_mut(),
                token_id(),
                ChainNameRaw::try_from("bananas").unwrap(),
                ethereum(),
                decimals,
                supply.clone()
            ),
            Error,
            Error::ChainNotRegistered { .. }
        );

        assert_err_contains!(
            register_p2p_token_instance(
                deps.as_mut(),
                token_id(),
                ethereum(),
                ChainNameRaw::try_from("bananas").unwrap(),
                decimals,
                supply.clone()
            ),
            Error,
            Error::ChainNotRegistered { .. }
        );
    }

    #[test]
    fn register_p2p_token_should_init_balance_tracking() {
        let mut deps = mock_dependencies();
        init(&mut deps);

        let decimals = 18;
        assert_ok!(register_p2p_token_instance(
            deps.as_mut(),
            token_id(),
            ethereum(),
            ethereum(),
            decimals,
            msg::TokenSupply::Untracked
        ));

        let supply = msg::TokenSupply::Tracked(Uint256::one());
        assert_ok!(register_p2p_token_instance(
            deps.as_mut(),
            token_id(),
            solana(),
            ethereum(),
            decimals,
            supply.clone(),
        ));

        let transfer_amount = Uint256::one().try_into().unwrap();

        // initial supply is one token. first transfer should succeed
        assert_ok!(transfer_token(
            deps.as_mut(),
            solana(),
            ethereum(),
            token_id(),
            transfer_amount
        ));

        assert_err_contains!(
            transfer_token(
                deps.as_mut(),
                solana(),
                ethereum(),
                token_id(),
                transfer_amount
            ),
            Error,
            Error::TokenSupplyInvariantViolated { .. }
        );
    }

    // Below are various helper functions to assist with writing tests

    fn its_address() -> nonempty::HexBinary {
        HexBinary::from_hex(ITS_ADDRESS)
            .unwrap()
            .try_into()
            .unwrap()
    }

    // most tests only need one token id
    fn token_id() -> TokenId {
        TokenId::new([7u8; 32])
    }

    fn xrpl() -> ChainNameRaw {
        XRPL.try_into().unwrap()
    }

    fn solana() -> ChainNameRaw {
        SOLANA.try_into().unwrap()
    }

    fn ethereum() -> ChainNameRaw {
        ETHEREUM.try_into().unwrap()
    }

    fn cc_id(source_chain: ChainNameRaw) -> CrossChainId {
        CrossChainId {
            source_chain,
            message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32).into(),
        }
    }

    fn get_supply(
        deps: DepsMut,
        chain: ChainNameRaw,
        token_id: TokenId,
    ) -> Result<TokenSupply, Error> {
        state::may_load_token_instance(deps.storage, chain.clone(), token_id)
            .unwrap()
            .ok_or(report!(Error::TokenNotDeployed { token_id, chain }))
            .map(|token| token.supply)
    }

    fn transfer_token(
        deps: DepsMut,
        from: ChainNameRaw,
        to: ChainNameRaw,
        token_id: TokenId,
        amount: nonempty::Uint256,
    ) -> Result<Response, Error> {
        let msg = HubMessage::SendToHub {
            destination_chain: to,
            message: InterchainTransfer {
                token_id,
                source_address: its_address(),
                destination_address: its_address(),
                amount,
                data: None,
            }
            .into(),
        };
        execute_message(
            deps,
            cc_id(from),
            ITS_ADDRESS.to_string().try_into().unwrap(),
            hub_message_abi_encode(msg.clone()),
        )
    }

    fn deploy_token(
        deps: DepsMut,
        from: ChainNameRaw,
        to: ChainNameRaw,
        token_id: TokenId,
    ) -> Result<Response, Error> {
        deploy_token_with_metadata(
            deps,
            from,
            to,
            token_id,
            "Test".parse().unwrap(),
            "TEST".parse().unwrap(),
            18,
            None,
        )
    }

    fn deploy_token_custom_minter(
        deps: DepsMut,
        from: ChainNameRaw,
        to: ChainNameRaw,
        token_id: TokenId,
        minter: nonempty::HexBinary,
    ) -> Result<Response, Error> {
        deploy_token_with_metadata(
            deps,
            from,
            to,
            token_id,
            "Test".parse().unwrap(),
            "TEST".parse().unwrap(),
            18,
            Some(minter),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn deploy_token_with_metadata(
        deps: DepsMut,
        from: ChainNameRaw,
        to: ChainNameRaw,
        token_id: TokenId,
        name: nonempty::String,
        symbol: nonempty::String,
        decimals: u8,
        minter: Option<nonempty::HexBinary>,
    ) -> Result<Response, Error> {
        let msg = HubMessage::SendToHub {
            destination_chain: to,
            message: DeployInterchainToken {
                token_id,
                name,
                symbol,
                decimals,
                minter,
            }
            .into(),
        };

        execute_message(
            deps,
            cc_id(from),
            ITS_ADDRESS.to_string().try_into().unwrap(),
            hub_message_abi_encode(msg.clone()),
        )
    }

    fn register_custom_token(
        deps: &mut OwnedDeps<MemoryStorage, MockApi, MockQuerier>,
        chain: ChainNameRaw,
        decimals: u8,
        token_address: nonempty::HexBinary,
    ) {
        let msg = HubMessage::RegisterTokenMetadata(RegisterTokenMetadata {
            decimals,
            token_address: token_address.clone(),
        });

        let res = assert_ok!(execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            hub_message_abi_encode(msg.clone()),
        ));
        assert_eq!(res.messages.len(), 0);
    }

    fn link_custom_token(
        deps: &mut OwnedDeps<MemoryStorage, MockApi, MockQuerier>,
        token_id: TokenId,
        source_chain: ChainNameRaw,
        destination_chain: ChainNameRaw,
        token_address: nonempty::HexBinary,
    ) {
        let msg = HubMessage::SendToHub {
            destination_chain: destination_chain.clone(),
            message: LinkToken {
                token_id,
                token_manager_type: Uint256::zero(),
                source_token_address: token_address.clone(),
                destination_token_address: token_address.clone(),
                params: None,
            }
            .into(),
        };

        let res = assert_ok!(execute_message(
            deps.as_mut(),
            CrossChainId {
                source_chain: source_chain.clone(),
                message_id: HexTxHashAndEventIndex::new([1u8; 32], 0u32)
                    .to_string()
                    .try_into()
                    .unwrap(),
            },
            ITS_ADDRESS.to_string().try_into().unwrap(),
            hub_message_abi_encode(msg.clone()),
        ));
        assert_eq!(res.messages.len(), 1);
    }

    fn register_and_link_custom_tokens(
        deps: &mut OwnedDeps<MemoryStorage, MockApi, MockQuerier>,
        token_id: TokenId,
        source_chain: ChainNameRaw,
        destination_chain: ChainNameRaw,
        source_decimals: u8,
        destination_decimals: u8,
        token_address: nonempty::HexBinary,
    ) {
        register_custom_token(
            deps,
            source_chain.clone(),
            source_decimals,
            token_address.clone(),
        );
        register_custom_token(
            deps,
            destination_chain.clone(),
            destination_decimals,
            token_address.clone(),
        );

        link_custom_token(
            deps,
            token_id,
            source_chain,
            destination_chain,
            token_address,
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
                operator: MockApi::default().addr_make("operator-address")
            },
        ));

        assert_ok!(killswitch::init(
            deps.as_mut().storage,
            killswitch::State::Disengaged
        ));

        for chain_name in [SOLANA, ETHEREUM, XRPL, AXELAR] {
            let chain = ChainNameRaw::try_from(chain_name).unwrap();
            assert_ok!(register_chain(
                &mut deps.as_mut(),
                msg::ChainConfig {
                    chain: chain.clone(),
                    its_edge_contract: ITS_ADDRESS.to_string().try_into().unwrap(),
                    truncation: TruncationConfig {
                        max_uint_bits: 256.try_into().unwrap(),
                        max_decimals_when_truncating: 18u8
                    },
                    translation_contract: MockApi::default()
                        .addr_make("translation")
                        .to_string()
                        .try_into()
                        .unwrap(),
                }
            ));
        }
        deps.querier.update_wasm(move |msg| match msg {
            WasmQuery::Smart { contract_addr, msg }
                if contract_addr == MockApi::default().addr_make(AXELARNET_GATEWAY).as_str() =>
            {
                let msg = from_json::<QueryMsg>(msg).unwrap();
                match msg {
                    QueryMsg::ChainName {} => {
                        Ok(to_json_binary(&ChainName::try_from("axelar").unwrap()).into()).into()
                    }
                    _ => panic!("unsupported query"),
                }
            }
            WasmQuery::Smart { contract_addr, msg }
                if contract_addr == MockApi::default().addr_make("translation").as_str() =>
            {
                let msg =
                    from_json::<interchain_token_api::payload_translation::TranslationQueryMsg>(
                        msg,
                    )
                    .unwrap();
                match msg {
                    interchain_token_api::payload_translation::TranslationQueryMsg::FromBytes {
                        payload,
                    } => Ok(to_json_binary(
                        &abi_translation_contract::abi::hub_message_abi_decode(&payload).unwrap(),
                    )
                    .into())
                    .into(),
                    interchain_token_api::payload_translation::TranslationQueryMsg::ToBytes {
                        message,
                    } => Ok(to_json_binary(
                        &abi_translation_contract::abi::hub_message_abi_encode(message),
                    )
                    .into())
                    .into(),
                    _ => panic!("unsupported query"),
                }
            }
            _ => panic!("unexpected query: {:?}", msg),
        });
    }
}

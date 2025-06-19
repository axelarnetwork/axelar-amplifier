use axelar_wasm_std::nonempty;
use error_stack::{ensure, Result};
use router_api::ChainName;
use service_registry_api::{self, AuthorizationState, Verifier};
use state::VERIFIERS;

use super::*;
use crate::events::Event;
use crate::state::{
    self, save_new_service, update_count_based_on_state_transition, ServiceParamsOverride,
    UpdatedServiceParams, VerifierCountOperation,
};

#[allow(clippy::too_many_arguments)]
pub fn register_service(
    deps: DepsMut,
    service_name: String,
    coordinator_contract: Addr,
    min_num_verifiers: u16,
    max_num_verifiers: Option<u16>,
    min_verifier_bond: nonempty::Uint128,
    bond_denom: String,
    unbonding_period_days: u16,
    description: String,
) -> Result<Response, ContractError> {
    save_new_service(
        deps.storage,
        &service_name.clone(),
        Service {
            name: service_name.clone(),
            coordinator_contract,
            min_num_verifiers,
            max_num_verifiers,
            min_verifier_bond,
            bond_denom,
            unbonding_period_days,
            description,
        },
    )?;
    Ok(Response::new())
}

fn ensure_authorization_max_limit_respected(
    deps: &DepsMut,
    service_name: &String,
    verifiers: &[Addr],
) -> Result<(), ContractError> {
    let max_limit = state::service(deps.storage, service_name, None)?.max_num_verifiers;
    if let Some(max_limit) = max_limit {
        let authorzied_verifier_count =
            state::number_of_authorized_verifiers(deps.storage, service_name)?;

        let additional_authorizations =
            state::count_verifiers_becoming_authorized(deps.storage, service_name, verifiers)?;

        let total_after_update = authorzied_verifier_count
            .checked_add(additional_authorizations)
            .ok_or(ContractError::AuthorizedVerifiersExceedu16)?;

        ensure!(
            total_after_update <= max_limit,
            ContractError::VerifierLimitExceed
        );
    }

    Ok(())
}

pub fn update_verifier_authorization_status(
    deps: DepsMut,
    verifiers: Vec<Addr>,
    service_name: String,
    auth_state: AuthorizationState,
) -> Result<Response, ContractError> {
    ensure_service_exists(deps.storage, &service_name)?;

    if auth_state == AuthorizationState::Authorized {
        ensure_authorization_max_limit_respected(&deps, &service_name, &verifiers)?;
    }
    for verifier in verifiers {
        let previous_auth_state =
            state::get_verifier_auth_state(deps.storage, &service_name, &verifier)?;
        state::update_verifier_auth_state(
            deps.storage,
            &service_name,
            &verifier,
            auth_state.clone(),
        )?;
        update_count_based_on_state_transition(
            deps.storage,
            &service_name,
            &auth_state,
            previous_auth_state,
        )?;
    }

    Ok(Response::new())
}

pub fn update_service(
    deps: DepsMut,
    service_name: String,
    updated_service_params: UpdatedServiceParams,
) -> Result<Response, ContractError> {
    state::update_service(deps.storage, &service_name, updated_service_params)?;
    Ok(Response::new())
}

pub fn override_service_params(
    deps: DepsMut,
    service_name: String,
    chain: ChainName,
    service_params_override: ServiceParamsOverride,
) -> Result<Response, ContractError> {
    state::save_service_override(
        deps.storage,
        &service_name,
        &chain,
        &service_params_override,
    )?;

    Ok(Response::new())
}

pub fn remove_service_params_override(
    deps: DepsMut,
    service_name: String,
    chain: ChainName,
) -> Result<Response, ContractError> {
    state::remove_service_override(deps.storage, &service_name, &chain)?;

    Ok(Response::new())
}

pub fn bond_verifier(
    deps: DepsMut,
    info: MessageInfo,
    service_name: String,
) -> Result<Response, ContractError> {
    let service = state::service(deps.storage, &service_name, None)?;

    let bond: Option<nonempty::Uint128> = if !info.funds.is_empty() {
        Some(
            info.funds
                .iter()
                .find(|coin| coin.denom == service.bond_denom)
                .ok_or(ContractError::WrongDenom)?
                .amount
                .try_into()
                .map_err(ContractError::from)?,
        )
    } else {
        None // sender can rebond currently unbonding funds by just sending no new funds
    };

    VERIFIERS.update(
        deps.storage,
        (&service_name.clone(), &info.sender.clone()),
        |sw| -> std::result::Result<Verifier, ContractError> {
            match sw {
                Some(verifier) => Ok(state::bond_verifier(verifier, bond)?),
                None => Ok(Verifier {
                    address: info.sender,
                    bonding_state: BondingState::Bonded {
                        amount: bond.ok_or(ContractError::NoFundsToBond)?,
                    },
                    authorization_state: AuthorizationState::NotAuthorized,
                    service_name,
                }),
            }
        },
    )?;

    Ok(Response::new())
}

pub fn register_chains_support(
    deps: DepsMut,
    info: MessageInfo,
    service_name: String,
    chains: Vec<ChainName>,
) -> Result<Response, ContractError> {
    ensure_service_exists(deps.storage, &service_name)?;

    state::register_chains_support(
        deps.storage,
        service_name.clone(),
        chains.clone(),
        info.sender.clone(),
    )?;

    Ok(Response::new().add_event(Event::ChainsSupportRegistered {
        verifier: info.sender,
        service_name,
        chains,
    }))
}

pub fn deregister_chains_support(
    deps: DepsMut,
    info: MessageInfo,
    service_name: String,
    chains: Vec<ChainName>,
) -> Result<Response, ContractError> {
    ensure_service_exists(deps.storage, &service_name)?;

    state::deregister_chains_support(
        deps.storage,
        service_name.clone(),
        chains.clone(),
        info.sender.clone(),
    )?;

    Ok(Response::new().add_event(Event::ChainsSupportDeregistered {
        verifier: info.sender,
        service_name,
        chains,
    }))
}

pub fn unbond_verifier(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    service_name: String,
) -> Result<Response, ContractError> {
    let service = state::service(deps.storage, &service_name, None)?;

    let verifier = VERIFIERS
        .may_load(deps.storage, (&service_name, &info.sender))
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::VerifierNotFound)?;

    let coordinator: coordinator::Client =
        client::ContractClient::new(deps.querier, &service.coordinator_contract).into();

    let ready_to_unbond = coordinator
        .ready_to_unbond(verifier.address.to_string())
        .change_context(ContractError::FailedToUnbondVerifier)?;

    let verifier = state::unbond_verifier(verifier, ready_to_unbond, env.block.time)?;

    VERIFIERS
        .save(deps.storage, (&service_name, &info.sender), &verifier)
        .change_context(ContractError::StorageError)?;

    Ok(Response::new())
}

pub fn claim_stake(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    service_name: String,
) -> Result<Response, ContractError> {
    let service = state::service(deps.storage, &service_name, None)?;

    let verifier = VERIFIERS
        .may_load(deps.storage, (&service_name, &info.sender))
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::VerifierNotFound)?;

    let (verifier, released_bond) = state::claim_verifier_stake(
        verifier,
        env.block.time,
        service.unbonding_period_days as u64,
    )?;

    VERIFIERS
        .save(deps.storage, (&service_name, &info.sender), &verifier)
        .change_context(ContractError::StorageError)?;

    Ok(Response::new().add_message(BankMsg::Send {
        to_address: info.sender.into(),
        amount: [Coin {
            denom: service.bond_denom,
            amount: released_bond.into(),
        }]
        .to_vec(),
    }))
}

fn ensure_service_exists(
    storage: &dyn Storage,
    service_name: &String,
) -> Result<(), ContractError> {
    ensure!(
        state::has_service(storage, service_name),
        ContractError::ServiceNotFound
    );

    Ok(())
}

use axelar_wasm_std::nonempty;
use error_stack::{Result, ResultExt};
use router_api::ChainName;
use service_registry_api::{self, AuthorizationState, Verifier};
use state::VERIFIERS;

use super::*;
use crate::events::Event;
use crate::msg::UpdatedServiceParams;
use crate::state::{self};

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
    let key = &service_name.clone();

    SERVICES.update(
        deps.storage,
        key,
        |service| -> std::result::Result<Service, ContractError> {
            match service {
                None => Ok(Service {
                    name: service_name.clone(),
                    coordinator_contract,
                    min_num_verifiers,
                    max_num_verifiers,
                    min_verifier_bond,
                    bond_denom,
                    unbonding_period_days,
                    description,
                }),
                _ => Err(ContractError::ServiceAlreadyExists),
            }
        },
    )?;
    state::AUTHORIZED_VERIFIER_COUNT
        .save(deps.storage, &service_name, &0)
        .change_context(ContractError::StorageError)?;

    // Response with attributes? event?
    Ok(Response::new())
}

// count how many new verifiers will be updated to "Authorized" state
// ignore if re-uthorized
fn count_verifiers_updated_to_authorize(
    deps: &DepsMut,
    service_name: String,
    verifiers: &[Addr],
) -> Result<u16, ContractError> {
    let mut count = 0;
    for verifier in verifiers {
        match VERIFIERS
            .may_load(deps.storage, (&service_name, verifier))
            .change_context(ContractError::StorageError)?
        {
            Some(existing) if existing.authorization_state != AuthorizationState::Authorized => {
                count += 1;
            }
            None => {
                count += 1;
            }
            _ => {} // Already authorized, skip
        }
    }
    u16::try_from(count).change_context(ContractError::StorageError)
}

// increment or decrement the count of authorized verifiers for a service
fn increment_authorized_count(deps: &mut DepsMut, service_name: &str) -> Result<(), ContractError> {
    state::AUTHORIZED_VERIFIER_COUNT
        .update(
            deps.storage,
            service_name,
            |count| -> std::result::Result<u16, ContractError> {
                let current = count.ok_or(ContractError::ServiceNotFound)?;
                current.checked_add(1).ok_or(ContractError::StorageError)
            },
        )
        .change_context(ContractError::StorageError)?;
    Ok(())
}

fn decrement_authorized_count(deps: &mut DepsMut, service_name: &str) -> Result<(), ContractError> {
    state::AUTHORIZED_VERIFIER_COUNT
        .update(
            deps.storage,
            service_name,
            |count| -> std::result::Result<u16, ContractError> {
                match count {
                    Some(n) if n > 0 => Ok(n - 1),
                    _ => Err(ContractError::AuthurizedCounterFailed), // should never happend-> counter is corrupted
                }
            },
        )
        .change_context(ContractError::StorageError)?;
    Ok(())
}

// should never have two same verifier in the list, otherwise there will be problem in counting
fn deduplicate_verifiers(verifiers: Vec<Addr>) -> Vec<Addr> {
    if verifiers.len() <= 1 {
        return verifiers;
    }
    let mut seen = std::collections::HashSet::with_capacity(verifiers.len());
    verifiers
        .into_iter()
        .filter(|addr| seen.insert(addr.clone()))
        .collect()
}

pub fn update_verifier_authorization_status(
    mut deps: DepsMut,
    verifiers: Vec<Addr>,
    service_name: String,
    auth_state: AuthorizationState,
) -> Result<Response, ContractError> {
    let service = SERVICES
        .may_load(deps.storage, &service_name)
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::ServiceNotFound)?;
    // deduplicate verifiers to avoid processing the same address multiple times
    let verifiers: Vec<Addr> = deduplicate_verifiers(verifiers);
    // count how many verifiers will be updated to "Authorized" state, and check if it exceeds the limit
    if auth_state == AuthorizationState::Authorized {
        validate_max_verifiers_not_exceed(&deps, &service_name, &service, &verifiers)?;
    }

    for verifier in verifiers {
        // load the original state
        let old_state = VERIFIERS
            .may_load(deps.storage, (&service_name, &verifier))
            .change_context(ContractError::StorageError)?
            .map(|v| v.authorization_state);

        // update to auth_state
        VERIFIERS.update(
            deps.storage,
            (&service_name, &verifier),
            |sw| -> std::result::Result<Verifier, ContractError> {
                match sw {
                    Some(mut verifier) => {
                        verifier.authorization_state = auth_state.clone();
                        Ok(verifier)
                    }
                    None => Ok(Verifier {
                        address: verifier.clone(),
                        bonding_state: BondingState::Unbonded,
                        authorization_state: auth_state.clone(),
                        service_name: service_name.clone(),
                    }),
                }
            },
        )?;
        // update counter to keep track of authorized verifiers
        match (old_state, auth_state.clone()) {
            // case 1 : old state is Some, new state is different
            // authorized -> other , decrement counter
            // other -> authorized, increment counter
            (Some(old), new) => match (old, new) {
                (AuthorizationState::Authorized, AuthorizationState::NotAuthorized)
                | (AuthorizationState::Authorized, AuthorizationState::Jailed) => {
                    decrement_authorized_count(&mut deps, &service_name)?;
                }
                (AuthorizationState::NotAuthorized, AuthorizationState::Authorized)
                | (AuthorizationState::Jailed, AuthorizationState::Authorized) => {
                    increment_authorized_count(&mut deps, &service_name)?;
                }
                _ => {}
            },
            // case 2 : old state is None, new state is Authorized, increment counter
            (None, AuthorizationState::Authorized) => {
                increment_authorized_count(&mut deps, &service_name)?;
            }
            _ => {}
        }
    }

    Ok(Response::new())
}

fn validate_max_verifiers_not_exceed(
    deps: &DepsMut,
    service_name: &str,
    service: &Service,
    verifiers: &[Addr],
) -> Result<(), ContractError> {
    if let Some(max) = service.max_num_verifiers {
        let current_authorized = state::AUTHORIZED_VERIFIER_COUNT
            .may_load(deps.storage, service_name)
            .change_context(ContractError::StorageError)?
            .ok_or(ContractError::ServiceNotFound)?;

        let verifiers_to_authorize =
            count_verifiers_updated_to_authorize(deps, service_name.to_string(), verifiers)?;

        let new_total = current_authorized
            .checked_add(verifiers_to_authorize)
            .ok_or(ContractError::StorageError)?;

        if new_total > max {
            return Err(ContractError::MaxVerifiersExceeded(max, new_total - max).into());
        }
    }

    Ok(())
}

pub fn update_service(
    deps: DepsMut,
    service_name: String,
    updated_service_params: UpdatedServiceParams,
) -> Result<Response, ContractError> {
    // prevent UpdateService if a new lower max is set and that is below the current number of authorized verifiers
    if let Some(new_max) = updated_service_params.max_num_verifiers {
        let current_authorized = state::AUTHORIZED_VERIFIER_COUNT
            .may_load(deps.storage, &service_name)
            .change_context(ContractError::StorageError)?
            .ok_or(ContractError::ServiceNotFound)?;
        if let Some(max) = new_max {
            if max < current_authorized {
                return Err(
                    ContractError::MaxVerifiersSetBelowCurrent(max, current_authorized).into(),
                );
            }
        }
    }
    SERVICES.update(deps.storage, &service_name, |service| match service {
        None => Err(ContractError::ServiceNotFound),
        Some(service) => Ok(Service {
            min_num_verifiers: updated_service_params
                .min_num_verifiers
                .unwrap_or(service.min_num_verifiers),
            max_num_verifiers: updated_service_params
                .max_num_verifiers
                .unwrap_or(service.max_num_verifiers),
            min_verifier_bond: updated_service_params
                .min_verifier_bond
                .unwrap_or(service.min_verifier_bond),
            unbonding_period_days: updated_service_params
                .unbonding_period_days
                .unwrap_or(service.unbonding_period_days),
            ..service
        }),
    })?;
    Ok(Response::new())
}

pub fn bond_verifier(
    deps: DepsMut,
    info: MessageInfo,
    service_name: String,
) -> Result<Response, ContractError> {
    let service = SERVICES
        .may_load(deps.storage, &service_name)
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::ServiceNotFound)?;

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
    SERVICES
        .may_load(deps.storage, &service_name)
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::ServiceNotFound)?;

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
    SERVICES
        .may_load(deps.storage, &service_name)
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::ServiceNotFound)?;

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
    let service = SERVICES
        .may_load(deps.storage, &service_name)
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::ServiceNotFound)?;

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
    let service = SERVICES
        .may_load(deps.storage, &service_name)
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::ServiceNotFound)?;

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

use axelar_wasm_std::nonempty;
use error_stack::Result;
use router_api::ChainName;
use service_registry_api::{self, AuthorizationState, Verifier};
use state::VERIFIERS;

use super::*;
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
                    name: service_name,
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

    // Response with attributes? event?
    Ok(Response::new())
}

pub fn update_verifier_authorization_status(
    deps: DepsMut,
    verifiers: Vec<Addr>,
    service_name: String,
    auth_state: AuthorizationState,
) -> Result<Response, ContractError> {
    SERVICES
        .may_load(deps.storage, &service_name)
        .change_context(ContractError::StorageError)?
        .ok_or(ContractError::ServiceNotFound)?;

    for verifier in verifiers {
        VERIFIERS.update(
            deps.storage,
            (&service_name, &verifier.clone()),
            |sw| -> std::result::Result<Verifier, ContractError> {
                match sw {
                    Some(mut verifier) => {
                        verifier.authorization_state = auth_state.clone();
                        Ok(verifier)
                    }
                    None => Ok(Verifier {
                        address: verifier,
                        bonding_state: BondingState::Unbonded,
                        authorization_state: auth_state.clone(),
                        service_name: service_name.clone(),
                    }),
                }
            },
        )?;
    }

    Ok(Response::new())
}

pub fn update_service(
    deps: DepsMut,
    service_name: String,
    updated_service_params: UpdatedServiceParams,
) -> Result<Response, ContractError> {
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

    Ok(Response::new())
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

    state::deregister_chains_support(deps.storage, service_name.clone(), chains, info.sender)?;

    Ok(Response::new())
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

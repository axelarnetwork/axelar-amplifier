use crate::state::{self, Verifier};
use crate::state::{AuthorizationState, VERIFIERS};
use router_api::ChainName;

use super::*;

pub fn require_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.governance != info.sender {
        return Err(ContractError::Unauthorized);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn register_service(
    deps: DepsMut,
    service_name: String,
    coordinator_contract: Addr,
    min_num_verifiers: u16,
    max_num_verifiers: Option<u16>,
    min_verifier_bond: Uint128,
    bond_denom: String,
    unbonding_period_days: u16,
    description: String,
) -> Result<Response, ContractError> {
    let key = &service_name.clone();

    SERVICES.update(
        deps.storage,
        key,
        |service| -> Result<Service, ContractError> {
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
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    for verifier in verifiers {
        VERIFIERS.update(
            deps.storage,
            (&service_name, &verifier.clone()),
            |sw| -> Result<Verifier, ContractError> {
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

pub fn bond_verifier(
    deps: DepsMut,
    info: MessageInfo,
    service_name: String,
) -> Result<Response, ContractError> {
    let service = SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    let bond = if !info.funds.is_empty() {
        info.funds
            .iter()
            .find(|coin| coin.denom == service.bond_denom)
            .ok_or(ContractError::WrongDenom)?
            .amount
    } else {
        Uint128::zero() // sender can rebond currently unbonding funds by just sending no new funds
    };

    VERIFIERS.update(
        deps.storage,
        (&service_name.clone(), &info.sender.clone()),
        |sw| -> Result<Verifier, ContractError> {
            match sw {
                Some(verifier) => Ok(verifier.add_bond(bond)?),
                None => Ok(Verifier {
                    address: info.sender,
                    bonding_state: BondingState::Bonded { amount: bond },
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
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    VERIFIERS
        .may_load(deps.storage, (&service_name, &info.sender))?
        .ok_or(ContractError::VerifierNotFound)?;

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
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    VERIFIERS
        .may_load(deps.storage, (&service_name, &info.sender))?
        .ok_or(ContractError::VerifierNotFound)?;

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
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    let verifier = VERIFIERS
        .may_load(deps.storage, (&service_name, &info.sender))?
        .ok_or(ContractError::VerifierNotFound)?;

    let query = coordinator::msg::QueryMsg::ReadyToUnbond {
        worker_address: verifier.address.clone(),
    };
    let ready_to_unbond = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: service.coordinator_contract.into(),
        msg: to_json_binary(&query)?,
    }))?;

    let verifier = verifier.unbond(ready_to_unbond, env.block.time)?;

    VERIFIERS.save(deps.storage, (&service_name, &info.sender), &verifier)?;

    Ok(Response::new())
}

pub fn claim_stake(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    service_name: String,
) -> Result<Response, ContractError> {
    let service = SERVICES
        .may_load(deps.storage, &service_name)?
        .ok_or(ContractError::ServiceNotFound)?;

    let verifier = VERIFIERS
        .may_load(deps.storage, (&service_name, &info.sender))?
        .ok_or(ContractError::VerifierNotFound)?;

    let (verifier, released_bond) =
        verifier.claim_stake(env.block.time, service.unbonding_period_days as u64)?;

    VERIFIERS.save(deps.storage, (&service_name, &info.sender), &verifier)?;

    Ok(Response::new().add_message(BankMsg::Send {
        to_address: info.sender.into(),
        amount: [Coin {
            denom: service.bond_denom,
            amount: released_bond,
        }]
        .to_vec(), // TODO: isolate coins
    }))
}

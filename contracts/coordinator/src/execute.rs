use cosmwasm_std::{Addr, DepsMut, MessageInfo, Response};
use std::collections::HashSet;

use multisig::verifier_set::VerifierSet;
use router_api::ChainName;

use crate::error::ContractError;
use crate::state::{
    update_verifier_set_for_prover, ACTIVE_VERIFIER_SET_FOR_PROVER, CONFIG,
    NEXT_VERIFIER_SET_FOR_PROVER, PROVER_PER_CHAIN,
};

pub fn check_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.governance != info.sender {
        return Err(ContractError::Unauthorized);
    }
    Ok(())
}

pub fn register_prover(
    deps: DepsMut,
    chain_name: ChainName,
    new_prover_addr: Addr,
) -> Result<Response, ContractError> {
    PROVER_PER_CHAIN.save(deps.storage, chain_name.clone(), &(new_prover_addr))?;
    Ok(Response::new())
}

pub fn set_active_verifier_set(
    deps: DepsMut,
    info: MessageInfo,
    next_verifier_set: VerifierSet,
) -> Result<Response, ContractError> {
    ACTIVE_VERIFIER_SET_FOR_PROVER.save(deps.storage, info.sender, &(next_verifier_set))?;
    Ok(Response::new())
}

pub fn set_next_verifier_set(
    deps: DepsMut,
    info: MessageInfo,
    next_verifier_set: VerifierSet,
) -> Result<Response, ContractError> {
    NEXT_VERIFIER_SET_FOR_PROVER.save(deps.storage, info.sender, &(next_verifier_set))?;
    Ok(Response::new())
}

pub fn update_prover_union_set(
    deps: DepsMut,
    info: MessageInfo,
    union_set: HashSet<Addr>,
) -> Result<Response, ContractError> {
    update_verifier_set_for_prover(deps.storage, info.sender, union_set)?;
    Ok(Response::new())
}

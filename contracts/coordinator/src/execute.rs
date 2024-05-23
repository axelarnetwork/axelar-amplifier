use cosmwasm_std::{Addr, DepsMut, MessageInfo, Response};

use multisig::verifier_set::VerifierSet;
use router_api::ChainName;

use crate::error::ContractError;
use crate::state::{ACTIVE_VERIFIER_SET_FOR_PROVER, CONFIG, PROVER_PER_CHAIN};

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

pub fn set_active_worker_set(
    deps: DepsMut,
    info: MessageInfo,
    next_worker_set: VerifierSet,
) -> Result<Response, ContractError> {
    ACTIVE_VERIFIER_SET_FOR_PROVER.save(deps.storage, info.sender, &(next_worker_set))?;
    Ok(Response::new())
}

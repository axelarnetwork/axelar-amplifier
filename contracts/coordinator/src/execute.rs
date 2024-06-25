use cosmwasm_std::{Addr, DepsMut, MessageInfo, Response};
use std::collections::HashSet;

use router_api::ChainName;

use crate::error::ContractError;
use crate::state::{update_verifier_set_for_prover, CONFIG, PROVER_PER_CHAIN};

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
    verifiers: HashSet<Addr>,
) -> Result<Response, ContractError> {
    update_verifier_set_for_prover(deps.storage, info.sender, verifiers)?;
    Ok(Response::new())
}

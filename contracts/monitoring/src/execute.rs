use cosmwasm_std::{Addr, DepsMut, MessageInfo, Response};

use connection_router_api::ChainName;

use crate::error::ContractError;
use crate::state::{CONFIG, PROVERS_PER_CHAIN};

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
    let existing_provers = PROVERS_PER_CHAIN.may_load(deps.storage, chain_name.clone())?;
    let mut provers = existing_provers.unwrap_or_else(Vec::new);

    provers.push(new_prover_addr.clone());

    PROVERS_PER_CHAIN.save(deps.storage, chain_name.clone(), &(provers))?;
    Ok(Response::new())
}

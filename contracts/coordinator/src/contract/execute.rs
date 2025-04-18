use std::collections::HashSet;

use cosmwasm_std::{Addr, DepsMut, MessageInfo, Response};
use router_api::ChainName;

use crate::error::ContractError;
use crate::state::{save_chain_contracts, save_prover_for_chain, update_verifier_set_for_prover};

pub fn register_prover(
    deps: DepsMut,
    chain_name: ChainName,
    new_prover_addr: Addr,
) -> Result<Response, ContractError> {
    save_prover_for_chain(deps.storage, chain_name, new_prover_addr)?;
    Ok(Response::new())
}

pub fn register_chain(
    deps: DepsMut,
    chain_name: ChainName,
    prover_addr: Addr,
    gateway_addr: Addr,
    voting_verifier_address: Addr,
) -> Result<Response, ContractError> {
    save_chain_contracts(
        deps.storage,
        chain_name,
        prover_addr,
        gateway_addr,
        voting_verifier_address,
    )?;
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

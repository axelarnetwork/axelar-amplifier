use cosmwasm_std::{Addr, DepsMut, MessageInfo, Response};

use connection_router_api::ChainName;

use crate::error::ContractError;
use crate::state::{CONFIG, CONTRACTS_PER_CHAIN};

pub fn check_governance(deps: &DepsMut, info: MessageInfo) -> Result<(), ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if config.governance != info.sender {
        return Err(ContractError::Unauthorized);
    }
    Ok(())
}

pub fn register_chain_contracts(
    deps: DepsMut,
    chain_name: ChainName,
    verifier_contract: Addr,
    gateway_contract: Addr,
    prover_contract: Addr,
) -> Result<Response, ContractError> {
    CONTRACTS_PER_CHAIN.save(
        deps.storage,
        chain_name.clone(),
        &(verifier_contract, gateway_contract, prover_contract),
    )?;
    Ok(Response::new())
}

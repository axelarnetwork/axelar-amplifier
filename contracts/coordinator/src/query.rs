use crate::error::ContractError;
use crate::state::{ACTIVE_VERIFIER_SET_FOR_PROVER, NEXT_VERIFIERSET_FOR_PROVER, PROVER_PER_CHAIN};
use cosmwasm_std::{Addr, Deps, StdResult};
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;

pub fn prover(deps: Deps, chain_name: ChainName) -> Result<Addr, ContractError> {
    PROVER_PER_CHAIN
        .may_load(deps.storage, chain_name.clone())?
        .ok_or(ContractError::NoProversRegisteredForChain(chain_name))
}

pub fn active_verifier_set(deps: Deps, chain_name: ChainName) -> StdResult<Option<VerifierSet>> {
    match prover(deps, chain_name) {
        Ok(prover_address) => {
            let active_worker_set =
                ACTIVE_VERIFIER_SET_FOR_PROVER.may_load(deps.storage, prover_address)?;
            Ok(active_worker_set)
        }
        Err(_err) => Ok(None),
    }
}

// TODO: Use the chain name to find out which provers to query.
fn is_verifier_in_verifier_set(deps: Deps, verifier_address: &Addr) -> StdResult<bool> {
    let chain_names: StdResult<Vec<ChainName>> = PROVER_PER_CHAIN
        .keys(deps.storage, None, None, cosmwasm_std::Order::Ascending)
        .collect();

    for chain_name in chain_names? {
        if let Ok(prover_address) = PROVER_PER_CHAIN.load(deps.storage, chain_name) {
            if let Ok(Some(verifier_set)) =
                ACTIVE_VERIFIER_SET_FOR_PROVER.may_load(deps.storage, prover_address.clone())
            {
                if verifier_set
                    .signers
                    .values()
                    .any(|signer| signer.address == *verifier_address)
                {
                    return Ok(true);
                }
            }

            if let Ok(Some(verifier_set)) =
                NEXT_VERIFIERSET_FOR_PROVER.may_load(deps.storage, prover_address)
            {
                if verifier_set
                    .signers
                    .values()
                    .any(|signer| signer.address == *verifier_address)
                {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

pub fn check_verifier_ready_to_unbond(deps: Deps, verifier_address: Addr) -> StdResult<bool> {
    if is_verifier_in_verifier_set(deps, &verifier_address)? {
        return Ok(false);
    }
    Ok(true)
}

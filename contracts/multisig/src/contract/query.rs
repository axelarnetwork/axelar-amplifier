use error_stack::{report, Result};
use router_api::ChainName;

use super::*;
use crate::key::{KeyType, PublicKey};
use crate::multisig::Multisig;
use crate::state::{chain_by_prover, load_pub_key, load_session_signatures, prover_by_chain};
use crate::verifier_set::VerifierSet;
use crate::ContractError;

pub fn multisig(deps: Deps, session_id: Uint64) -> StdResult<Multisig> {
    let session = SIGNING_SESSIONS.load(deps.storage, session_id.into())?;

    let verifier_set = VERIFIER_SETS.load(deps.storage, &session.verifier_set_id)?;
    let signatures = load_session_signatures(deps.storage, session.id.u64())?;

    Ok(Multisig {
        state: session.state,
        verifier_set,
        signatures,
    })
}

pub fn verifier_set(deps: Deps, verifier_set_id: String) -> StdResult<VerifierSet> {
    VERIFIER_SETS.load(deps.storage, &verifier_set_id)
}

pub fn public_key(deps: Deps, verifier: Addr, key_type: KeyType) -> StdResult<PublicKey> {
    let raw = load_pub_key(deps.storage, verifier, key_type)?;
    Ok(PublicKey::try_from((key_type, raw)).expect("could not decode pub key"))
}

pub fn caller_authorized(
    storage: &dyn Storage,
    address: Addr,
    chain_name: ChainName,
) -> StdResult<bool> {
    Ok(chain_by_prover(storage, &address)?
        .filter(|c| c == &chain_name)
        .is_some())
}

pub fn prover_for_chain(deps: Deps, chain_name: ChainName) -> Result<Addr, ContractError> {
    prover_by_chain(deps.storage, chain_name.clone())
        .change_context(ContractError::InvalidChainName)?
        .ok_or(report!(ContractError::ProverNotFound(chain_name)))
}

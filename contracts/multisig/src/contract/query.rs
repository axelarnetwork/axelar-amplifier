use router_api::ChainName;

use super::*;
use crate::key::{KeyType, PublicKey};
use crate::multisig::Multisig;
use crate::state::{load_pub_key, load_session_signatures, AUTHORIZED_CALLERS};
use crate::verifier_set::VerifierSet;

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

pub fn caller_authorized(deps: Deps, address: Addr, chain_name: ChainName) -> StdResult<bool> {
    let is_authorized = AUTHORIZED_CALLERS.may_load(deps.storage, &address)? == Some(chain_name);
    Ok(is_authorized)
}

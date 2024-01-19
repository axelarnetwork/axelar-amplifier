use crate::{
    key::{KeyType, PublicKey},
    state::{load_session_signatures, PUB_KEYS},
    worker_set::WorkerSet,
};

use super::*;

pub fn get_multisig(deps: Deps, session_id: Uint64) -> StdResult<Multisig> {
    let session = SIGNING_SESSIONS.load(deps.storage, session_id.into())?;

    let worker_set = WORKER_SETS.load(deps.storage, &session.worker_set_id)?;
    let signatures = load_session_signatures(deps.storage, session.id.u64())?;

    let signers_with_sigs = worker_set
        .signers
        .into_iter()
        .map(|(address, signer)| (signer, signatures.get(&address).cloned()))
        .collect::<Vec<_>>();

    Ok(Multisig {
        state: session.state,
        quorum: worker_set.threshold,
        signers: signers_with_sigs,
    })
}

pub fn get_worker_set(deps: Deps, worker_set_id: String) -> StdResult<WorkerSet> {
    WORKER_SETS.load(deps.storage, &worker_set_id)
}

pub fn get_public_key(deps: Deps, worker: Addr, key_type: KeyType) -> StdResult<PublicKey> {
    let raw = PUB_KEYS.load(deps.storage, (worker, key_type))?;
    Ok(PublicKey::try_from((key_type, raw)).expect("could not decode pub key"))
}

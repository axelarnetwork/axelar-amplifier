use cosmwasm_std::{
    to_binary, Deps, QueryRequest, StdError, StdResult, Uint256, Uint64, WasmQuery,
};

use itertools::Itertools;
use multisig::{
    key::Signature,
    msg::{Multisig, Signer},
    types::MultisigState,
    worker_set::WorkerSet,
};

use crate::{
    msg::{GetProofResponse, ProofStatus},
    state::{COMMANDS_BATCH, CONFIG, CURRENT_WORKER_SET, MULTISIG_SESSION_BATCH},
};

pub fn get_proof(deps: Deps, multisig_session_id: Uint64) -> StdResult<GetProofResponse> {
    let config = CONFIG.load(deps.storage)?;

    let batch_id = MULTISIG_SESSION_BATCH.load(deps.storage, multisig_session_id.u64())?;

    let batch = COMMANDS_BATCH.load(deps.storage, &batch_id)?;
    assert_eq!(batch.encoder, config.encoder);

    let query_msg = multisig::msg::QueryMsg::GetMultisig {
        session_id: multisig_session_id,
    };

    let multisig: Multisig = deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
        contract_addr: config.multisig.to_string(),
        msg: to_binary(&query_msg)?,
    }))?;

    let status = match multisig.state {
        MultisigState::Pending => ProofStatus::Pending,
        MultisigState::Completed { .. } => {
            let execute_data = batch
                .encode_execute_data(
                    multisig.quorum,
                    optimize_signers(multisig.signers, multisig.quorum),
                )
                .map_err(|err| {
                    StdError::generic_err(format!("failed to encode execute data: {}", err))
                })?;

            ProofStatus::Completed { execute_data }
        }
    };

    Ok(GetProofResponse {
        multisig_session_id,
        message_ids: batch.message_ids,
        data: batch.data,
        status,
    })
}

pub fn get_worker_set(deps: Deps) -> StdResult<WorkerSet> {
    CURRENT_WORKER_SET.load(deps.storage)
}

/// Returns the minimum amount of signatures to satisfy the quorum, sorted by weight
fn optimize_signers(
    signers: Vec<(Signer, Option<Signature>)>,
    quorum: Uint256,
) -> Vec<(Signer, Option<Signature>)> {
    signers
        .into_iter()
        .sorted_by(|(a, _), (b, _)| b.weight.cmp(&a.weight))
        .scan(
            Uint256::zero(),
            |acc, (signer, signature)| match signature {
                Some(sig) if *acc < quorum => {
                    *acc += signer.weight;
                    Some((signer, Some(sig)))
                }
                _ => Some((signer, None)),
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{Addr, HexBinary};
    use multisig::key::{KeyType, PublicKey};

    use super::*;

    #[test]
    fn optimizing_sorts_and_removes_extra_sigs() {
        let quorum = Uint256::from(8u64);
        let signers: Vec<(Signer, Option<Signature>)> = vec![
            make_signer("addr1", 1, true),
            make_signer("addr2", 3, true),
            make_signer("addr3", 5, true),
            make_signer("addr4", 7, false),
            make_signer("addr5", 6, false),
            make_signer("addr6", 4, false),
            make_signer("addr7", 2, true),
        ];

        let expected_signers: Vec<(Signer, Option<Signature>)> = vec![
            make_signer("addr4", 7, false),
            make_signer("addr5", 6, false),
            make_signer("addr3", 5, true),
            make_signer("addr6", 4, false),
            make_signer("addr2", 3, true),
            make_signer("addr7", 2, false),
            make_signer("addr1", 1, false),
        ];

        let optimized = optimize_signers(signers, quorum);

        assert_eq!(optimized, expected_signers);
    }

    fn make_signer(address: &str, weight: u64, with_sig: bool) -> (Signer, Option<Signature>) {
        (
            Signer {
                address: Addr::unchecked(address),
                weight: Uint256::from(weight),
                pub_key: PublicKey::Ecdsa(
                    HexBinary::from_hex(
                        "033a9726a6e2fdc308089c6cab1e6fda2e2bddeb2bcf800990e5fd2c05a270c9df",
                    )
                    .unwrap(),
                ),
            },
            if with_sig {
                Some(
                    (
                        KeyType::Ecdsa,
                        HexBinary::from_hex("c55581edbf0401d0cd3495522323e45d4521312dafdedf39b4adc8085a3842c74f13c055b72d12ec3afc1e8f9c37b5f660fbefb38165dbe61090923865e15827").unwrap(),
                    )
                        .try_into()
                        .unwrap(),
                )
            } else {
                None
            },
        )
    }
}

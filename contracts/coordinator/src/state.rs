use std::collections::HashSet;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, Storage};
use cw_storage_plus::{index_list, IndexedMap, MultiIndex, UniqueIndex};
use router_api::ChainName;

use crate::error::ContractError;

type ProverAddress = Addr;
type VerifierAddress = Addr;

#[index_list(ProverAddress)]
struct ChainProverIndexes<'a> {
    pub by_prover: UniqueIndex<'a, ProverAddress, ProverAddress, ChainName>,
}

const CHAIN_PROVER_INDEXED_MAP: IndexedMap<ChainName, ProverAddress, ChainProverIndexes> =
    IndexedMap::new(
        "chain_prover_map",
        ChainProverIndexes {
            by_prover: UniqueIndex::new(|prover| prover.clone(), "chain_prover_map_by_prover"),
        },
    );

pub fn is_prover_registered(
    storage: &dyn Storage,
    prover_address: ProverAddress,
) -> Result<bool, ContractError> {
    Ok(CHAIN_PROVER_INDEXED_MAP
        .idx
        .by_prover
        .item(storage, prover_address)?
        .is_some())
}

#[allow(dead_code)] // Used in tests, might be useful in future query
pub fn load_prover_by_chain(
    storage: &dyn Storage,
    chain_name: ChainName,
) -> Result<ProverAddress, ContractError> {
    CHAIN_PROVER_INDEXED_MAP
        .may_load(storage, chain_name)?
        .ok_or(ContractError::ProverNotRegistered)
}

pub fn save_prover_for_chain(
    storage: &mut dyn Storage,
    chain: ChainName,
    prover: ProverAddress,
) -> Result<(), ContractError> {
    CHAIN_PROVER_INDEXED_MAP.save(storage, chain.clone(), &prover)?;
    Ok(())
}

#[index_list(VerifierProverRecord)]
pub struct VerifierSetIndex<'a> {
    pub by_verifier:
        MultiIndex<'a, VerifierAddress, VerifierProverRecord, (ProverAddress, VerifierAddress)>,
}

#[cw_serde]
pub struct VerifierProverRecord {
    pub prover: ProverAddress,
    pub verifier: VerifierAddress,
}

pub const VERIFIER_PROVER_INDEXED_MAP: IndexedMap<
    (ProverAddress, VerifierAddress),
    VerifierProverRecord,
    VerifierSetIndex,
> = IndexedMap::new(
    "verifier_prover_map",
    VerifierSetIndex {
        by_verifier: MultiIndex::new(
            |_pk: &[u8], d| d.verifier.clone(),
            "verifier_prover_map",
            "verifier_prover_map_by_verifier",
        ),
    },
);

pub fn update_verifier_set_for_prover(
    storage: &mut dyn Storage,
    prover_address: ProverAddress,
    new_verifiers: HashSet<VerifierAddress>,
) -> Result<(), ContractError> {
    let existing_verifiers = VERIFIER_PROVER_INDEXED_MAP
        .prefix(prover_address.clone())
        .keys(storage, None, None, Order::Ascending)
        .filter_map(Result::ok)
        .collect::<HashSet<VerifierAddress>>();

    for verifier in existing_verifiers.difference(&new_verifiers) {
        VERIFIER_PROVER_INDEXED_MAP
            .remove(storage, (prover_address.clone(), verifier.clone()))
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to remove verifier {:?} for prover {:?}",
                    verifier, prover_address
                )
            });
    }

    for verifier in new_verifiers.difference(&existing_verifiers) {
        VERIFIER_PROVER_INDEXED_MAP.save(
            storage,
            (prover_address.clone(), verifier.clone()),
            &VerifierProverRecord {
                prover: prover_address.clone(),
                verifier: verifier.clone(),
            },
        )?;
    }

    Ok(())
}

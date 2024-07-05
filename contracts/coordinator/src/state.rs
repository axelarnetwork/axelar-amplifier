use crate::error::ContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, Storage};
use cw_storage_plus::{Index, IndexList, IndexedMap, Map, MultiIndex};
use router_api::ChainName;
use std::collections::HashSet;

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
type ProverAddress = Addr;

pub const PROVER_PER_CHAIN: Map<ChainName, ProverAddress> = Map::new("prover_per_chain");

pub struct VerifierSetIndex<'a> {
    pub by_verifier: MultiIndex<'a, Addr, VerifierProverRecord, (Addr, Addr)>,
}

impl<'a> IndexList<VerifierProverRecord> for VerifierSetIndex<'a> {
    fn get_indexes(&self) -> Box<dyn Iterator<Item = &dyn Index<VerifierProverRecord>> + '_> {
        let v: Vec<&dyn Index<VerifierProverRecord>> = vec![&self.by_verifier];
        Box::new(v.into_iter())
    }
}

#[cw_serde]
pub struct VerifierProverRecord {
    pub prover: ProverAddress,
    pub verifier: Addr,
}

pub const VERIFIER_PROVER_INDEXED_MAP: IndexedMap<
    (Addr, Addr),
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
    new_verifiers: HashSet<Addr>,
) -> Result<(), ContractError> {
    let existing_verifiers = VERIFIER_PROVER_INDEXED_MAP
        .prefix(prover_address.clone())
        .keys(storage, None, None, Order::Ascending)
        .filter_map(Result::ok)
        .collect::<HashSet<Addr>>();

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

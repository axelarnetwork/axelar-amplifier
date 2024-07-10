use crate::error::ContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, Storage};
use cw_storage_plus::{Index, IndexList, IndexedMap, MultiIndex, UniqueIndex};
use router_api::ChainName;
use std::collections::HashSet;

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
type ProverAddress = Addr;
type VerifierAddress = Addr;

struct ChainProverIndexes<'a> {
    pub by_chain: UniqueIndex<'a, ChainName, ChainProverRecord, (ChainName, ProverAddress)>,
    pub by_prover: UniqueIndex<'a, ProverAddress, ChainProverRecord, (ChainName, ProverAddress)>,
}

impl<'a> IndexList<ChainProverRecord> for ChainProverIndexes<'a> {
    fn get_indexes(&self) -> Box<dyn Iterator<Item = &dyn Index<ChainProverRecord>> + '_> {
        let v: Vec<&dyn Index<ChainProverRecord>> = vec![&self.by_chain, &self.by_prover];
        Box::new(v.into_iter())
    }
}

#[cw_serde]
pub struct ChainProverRecord {
    pub prover: ProverAddress,
    pub chain: ChainName,
}

const CHAIN_PROVER_INDEXED_MAP: IndexedMap<
    (ChainName, ProverAddress),
    ChainProverRecord,
    ChainProverIndexes,
> = IndexedMap::new(
    "chain_prover_map",
    ChainProverIndexes {
        by_chain: UniqueIndex::new(|d| d.chain.clone(), "chain_prover_map_by_chain"),
        by_prover: UniqueIndex::new(|d| d.prover.clone(), "chain_prover_map_by_prover"),
    },
);

pub fn load_chain_by_prover(
    storage: &dyn Storage,
    prover_address: ProverAddress,
) -> Result<ChainProverRecord, ContractError> {
    CHAIN_PROVER_INDEXED_MAP
        .idx
        .by_prover
        .item(storage, prover_address)?
        .map(|(_, r)| r)
        .ok_or(ContractError::ProverNotRegistered)
}

#[allow(dead_code)] // Used in tests, might be useful in future query
pub fn load_prover_by_chain(
    storage: &dyn Storage,
    chain_name: ChainName,
) -> Result<ChainProverRecord, ContractError> {
    CHAIN_PROVER_INDEXED_MAP
        .idx
        .by_chain
        .item(storage, chain_name)?
        .map(|(_, r)| r)
        .ok_or(ContractError::ProverNotRegistered)
}

pub fn save_prover_for_chain(
    storage: &mut dyn Storage,
    chain: ChainName,
    prover: ProverAddress,
) -> Result<(), ContractError> {
    CHAIN_PROVER_INDEXED_MAP.save(
        storage,
        (chain.clone(), prover.clone()),
        &ChainProverRecord { prover, chain },
    )?;
    Ok(())
}

pub struct VerifierSetIndex<'a> {
    pub by_verifier:
        MultiIndex<'a, VerifierAddress, VerifierProverRecord, (ProverAddress, VerifierAddress)>,
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

use std::collections::HashSet;

use axelar_wasm_std::counter::Counter;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Order, Storage};
use cw_storage_plus::{index_list, Index, IndexList, IndexedMap, Item, Map, MultiIndex, UniqueIndex};
use error_stack::{report, Result, ResultExt};
use router_api::{ChainName, Gateway};

use crate::msg::ChainContractsResponse;

type ProverAddress = Addr;
type GatewayAddress = Addr;
type VerifierAddress = Addr;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("chain {0} is not registered")]
    ChainNotRegistered(ChainName),

    #[error("prover {0} is not registered")]
    ProverNotRegistered(Addr),

    #[error("gateway {0} is not registered")]
    GatewayNotRegistered(Addr),

    #[error("verifier {0} is not registered")]
    VerifierNotRegistered(Addr),

    #[error("failed to parse state data")]
    StateParseFailed,

    #[error("failed to save state data")]
    StateSaveFailed,

    #[error("failed to remove state data")]
    StateRemoveFailed,
}

#[cw_serde]
pub struct Config {
    pub service_registry: Addr,
    pub router: Addr,
    pub multisig: Addr,
}
pub const CONFIG: Item<Config> = Item::new("config");

pub fn load_config(storage: &dyn Storage) -> Config {
    CONFIG
        .load(storage)
        .expect("coordinator config must be set during instantiation")
}

#[cw_serde]
pub struct ChainContracts {
    pub gateway: Addr,
    pub voting_verifier: Addr,
    pub multisig_prover: Addr,
}

pub const INSTANTIATE2_COUNTER: Counter<u64> = Counter::new("instantiate2_counter");
pub const DEPLOYED_CHAINS: Map<String, ChainContracts> = Map::new("deployed_chains");

/// Records the contract addresses for a specific chain
#[cw_serde]
pub struct ChainContractsRecord {
    pub chain_name: ChainName,
    pub prover_address: ProverAddress,
    pub gateway_address: GatewayAddress,
    pub verifier_address: VerifierAddress,
}

impl From<ChainContractsRecord> for ChainContractsResponse {
    fn from(chain_contracts_record: ChainContractsRecord) -> Self {
        ChainContractsResponse {
            chain_name: chain_contracts_record.chain_name,
            prover_address: chain_contracts_record.prover_address,
            gateway_address: chain_contracts_record.gateway_address,
            verifier_address: chain_contracts_record.verifier_address,
        }
    }
}

pub struct ChainContractsIndexes<'a> {
    pub by_prover: UniqueIndex<'a, ProverAddress, ChainContractsRecord, ChainName>,
    pub by_gateway: UniqueIndex<'a, GatewayAddress, ChainContractsRecord, ChainName>,
    pub by_verifier: UniqueIndex<'a, VerifierAddress, ChainContractsRecord, ChainName>,
}

impl IndexList<ChainContractsRecord> for ChainContractsIndexes<'_> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<ChainContractsRecord>> + '_> {
        let v: Vec<&dyn Index<ChainContractsRecord>> =
            vec![&self.by_prover, &self.by_gateway, &self.by_verifier];
        Box::new(v.into_iter())
    }
}

const CHAIN_CONTRACTS_MAP: IndexedMap<ChainName, ChainContractsRecord, ChainContractsIndexes> =
    IndexedMap::new(
        "chain_contracts_map",
        ChainContractsIndexes {
            by_prover: UniqueIndex::new(|r| r.prover_address.clone(), "chain_contracts_by_prover"),
            by_gateway: UniqueIndex::new(
                |r| r.gateway_address.clone(),
                "chain_contracts_by_gateway",
            ),
            by_verifier: UniqueIndex::new(
                |r| r.verifier_address.clone(),
                "chain_contracts_by_verifier",
            ),
        },
    );

pub fn save_chain_contracts(
    storage: &mut dyn Storage,
    chain: ChainName,
    prover_address: ProverAddress,
    gateway_address: GatewayAddress,
    verifier_address: VerifierAddress,
) -> Result<(), Error> {
    let record = ChainContractsRecord {
        chain_name: chain.clone(),
        prover_address,
        gateway_address,
        verifier_address,
    };

    CHAIN_CONTRACTS_MAP
        .save(storage, chain, &record)
        .change_context(Error::StateSaveFailed)?;

    Ok(())
}

pub fn contracts_by_chain(
    storage: &dyn Storage,
    chain_name: ChainName,
) -> Result<ChainContractsRecord, Error> {
    CHAIN_CONTRACTS_MAP
        .may_load(storage, chain_name.clone())
        .change_context(Error::StateParseFailed)?
        .ok_or(report!(Error::ChainNotRegistered(chain_name)))
}

pub fn contracts_by_prover(
    storage: &dyn Storage,
    prover_address: ProverAddress,
) -> Result<ChainContractsRecord, Error> {
    Ok(CHAIN_CONTRACTS_MAP
        .idx
        .by_prover
        .item(storage, prover_address.clone())
        .change_context(Error::StateParseFailed)?
        .ok_or(Error::ProverNotRegistered(prover_address))?
        .1)
}

pub fn contracts_by_gateway(
    storage: &dyn Storage,
    gateway_address: GatewayAddress,
) -> Result<ChainContractsRecord, Error> {
    Ok(CHAIN_CONTRACTS_MAP
        .idx
        .by_gateway
        .item(storage, gateway_address.clone())
        .change_context(Error::StateParseFailed)?
        .ok_or(Error::GatewayNotRegistered(gateway_address))?
        .1)
}

pub fn contracts_by_verifier(
    storage: &dyn Storage,
    verifier_address: VerifierAddress,
) -> Result<ChainContractsRecord, Error> {
    Ok(CHAIN_CONTRACTS_MAP
        .idx
        .by_verifier
        .item(storage, verifier_address.clone())
        .change_context(Error::StateParseFailed)?
        .ok_or(Error::VerifierNotRegistered(verifier_address))?
        .1)
}

// Legacy prover storage - maintained for backward compatibility
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
) -> Result<bool, Error> {
    Ok(CHAIN_PROVER_INDEXED_MAP
        .idx
        .by_prover
        .item(storage, prover_address)
        .change_context(Error::StateParseFailed)?
        .is_some())
}

#[allow(dead_code)] // Used in tests, might be useful in future query
pub fn load_prover_by_chain(
    storage: &dyn Storage,
    chain_name: ChainName,
) -> Result<ProverAddress, Error> {
    Ok(CHAIN_PROVER_INDEXED_MAP
        .may_load(storage, chain_name.clone())
        .change_context(Error::StateParseFailed)?
        .ok_or(Error::ChainNotRegistered(chain_name))?)
}

pub fn save_prover_for_chain(
    storage: &mut dyn Storage,
    chain: ChainName,
    prover: ProverAddress,
) -> Result<(), Error> {
    CHAIN_PROVER_INDEXED_MAP
        .save(storage, chain.clone(), &prover)
        .change_context(Error::StateSaveFailed)?;

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
) -> Result<(), Error> {
    let existing_verifiers = VERIFIER_PROVER_INDEXED_MAP
        .prefix(prover_address.clone())
        .keys(storage, None, None, Order::Ascending)
        .filter_map(core::result::Result::ok)
        .collect::<HashSet<VerifierAddress>>();

    for verifier in existing_verifiers.difference(&new_verifiers) {
        VERIFIER_PROVER_INDEXED_MAP
            .remove(storage, (prover_address.clone(), verifier.clone()))
            .change_context(Error::StateRemoveFailed)?;
    }

    for verifier in new_verifiers.difference(&existing_verifiers) {
        VERIFIER_PROVER_INDEXED_MAP
            .save(
                storage,
                (prover_address.clone(), verifier.clone()),
                &VerifierProverRecord {
                    prover: prover_address.clone(),
                    verifier: verifier.clone(),
                },
            )
            .change_context(Error::StateSaveFailed)?;
    }

    Ok(())
}

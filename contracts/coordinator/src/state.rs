use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use multisig::verifier_set::VerifierSet;
use router_api::ChainName;
use std::collections::HashSet;

#[cw_serde]
pub struct Config {
    pub governance: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

type ProverAddress = Addr;

pub const PROVER_PER_CHAIN: Map<ChainName, ProverAddress> = Map::new("prover_per_chain");

// TODO: migrate this?
pub const ACTIVE_VERIFIER_SET_FOR_PROVER: Map<ProverAddress, VerifierSet> =
    Map::new("active_prover_verifier_set");

type ChainNames = HashSet<ChainName>;
type VerifierAddress = Addr;
pub const CHAINS_OF_VERIFIER: Map<VerifierAddress, ChainNames> = Map::new("chains_of_verifier");

pub const NEXT_VERIFIER_SET_FOR_PROVER: Map<ProverAddress, VerifierSet> =
    Map::new("next_prover_verifier");

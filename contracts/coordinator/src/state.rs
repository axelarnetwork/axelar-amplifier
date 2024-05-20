use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use multisig::worker_set::WorkerSet;
use router_api::ChainName;
use std::collections::HashSet;

#[cw_serde]
pub struct Config {
    pub governance: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

type ProverAddress = Addr;

pub const PROVER_PER_CHAIN: Map<ChainName, ProverAddress> = Map::new("prover_per_chain");

type ChainNames = HashSet<ChainName>;
type WorkerAddress = Addr;
pub const CHAINS_OF_WORKER: Map<WorkerAddress, ChainNames> = Map::new("chains_of_worker");

pub const ACTIVE_WORKERSET_FOR_PROVER: Map<ProverAddress, WorkerSet> =
    Map::new("active_prover_workerset");

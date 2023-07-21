use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Timestamp, Uint128};
use cw_storage_plus::{Index, IndexList, IndexedMap, Map, MultiIndex};

use axelar_wasm_std::{nonempty::Error, snapshot::Participant};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Service {
    pub name: String,
    pub service_contract: Addr,
    pub min_num_workers: u16,
    pub max_num_workers: Option<u16>,
    pub min_worker_bond: Uint128,
    pub unbonding_period_days: u16,
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Worker {
    pub address: Addr,
    pub stake: Uint128, // TODO: correct size?
    pub commission_rate: Uint128,
    pub state: WorkerState,
    pub service_name: String,
}

impl TryInto<Participant> for Worker {
    type Error = Error;

    fn try_into(self) -> Result<Participant, Error> {
        Ok(Participant {
            address: self.address,
            weight: self.stake.try_into()?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum WorkerState {
    Active,
    Deregistering { deregistered_at: Timestamp },
    Inactive,
}

pub struct WorkerIndexes<'a> {
    pub service_name: MultiIndex<'a, String, Worker, &'a Addr>,
}

impl<'a> IndexList<Worker> for WorkerIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<Worker>> + '_> {
        let v: Vec<&dyn Index<Worker>> = vec![&self.service_name];
        Box::new(v.into_iter())
    }
}

pub fn service_workers<'a>() -> IndexedMap<'a, &'a Addr, Worker, WorkerIndexes<'a>> {
    let indexes = WorkerIndexes {
        service_name: MultiIndex::new(
            |_pk, d| d.service_name.clone(),
            "worker_services",
            "worker_services__service_name",
        ),
    };
    IndexedMap::new("worker_services", indexes)
}

pub const SERVICES: Map<&str, Service> = Map::new("services");

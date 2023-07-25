use cosmwasm_schema::cw_serde;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Timestamp, Uint128};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub governance: Addr,
}

pub const CONFIG: Item<Config> = Item::new("config");

use axelar_wasm_std::snapshot::Participant;

use crate::ContractError;

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
    pub bonding_state: BondingState,
    pub authorization_state: AuthorizationState,
    pub service_name: String,
}

impl TryInto<Participant> for Worker {
    type Error = ContractError;

    fn try_into(self) -> Result<Participant, ContractError> {
        match self.bonding_state {
            BondingState::Bonded { amount } => Ok(Participant {
                address: self.address,
                weight: amount.try_into()?,
            }),
            _ => Err(ContractError::WorkerNotBonded {}),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum BondingState {
    Bonded {
        amount: Uint128,
    },
    RequestedUnbonding {
        amount: Uint128,
    },
    Unbonding {
        amount: Uint128,
        unbonded_at: Timestamp,
    }, // authorized, but requested unbond. stake still held but unbonding countdown started
    Unbonded, // authorized, but not bonded, or bonded stake does not meet minimum
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub enum AuthorizationState {
    NotAuthorized,
    Authorized,
}

// maps service_name -> Service
pub const SERVICES: Map<&str, Service> = Map::new("services");
// maps (service_name, chain_name, worker_address) -> ()
pub const WORKERS_PER_CHAIN: Map<(&str, &str, &Addr), ()> = Map::new("workers_per_chain");
// maps (service_name, worker_address) -> Worker
pub const WORKERS: Map<(&str, &Addr), Worker> = Map::new("workers");

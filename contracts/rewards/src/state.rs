use std::collections::HashMap;

use axelar_wasm_std::{nonempty, Threshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage, Uint128};
use cw_storage_plus::{Item, Map};
use error_stack::{Result, ResultExt};
use mockall::automock;

use crate::{error::ContractError, msg::Params};

#[cw_serde]
pub struct Config {
    pub governance: Addr,
    pub rewards_denom: String,
}

#[cw_serde]
pub struct StoredParams {
    pub params: Params,
    /// epoch in which the params were updated
    pub last_updated: Epoch,
}

#[cw_serde]
pub struct EpochTally {
    pub contract: Addr,
    pub event_count: u64,
    pub participation: HashMap<String, u64>, // maps a worker address to participation count. Can't use Addr as key else deserialization will fail
    pub epoch: Epoch,
    pub params: Params,
}

impl EpochTally {
    pub fn new(contract: Addr, epoch: Epoch, params: Params) -> Self {
        EpochTally {
            contract,
            event_count: 0,
            participation: HashMap::new(),
            epoch,
            params,
        }
    }

    /// IMPORTANT: worker address must be validated before calling this function
    /// TODO: panic if address is invalid?
    pub fn record_participation(mut self, worker: Addr) -> Self {
        self.participation
            .entry(worker.to_string())
            .and_modify(|count| *count += 1)
            .or_insert(1);
        self
    }

    pub fn increment_event_count(mut self) -> Self {
        self.event_count += 1;
        self
    }

    pub fn workers_to_reward(&self) -> Vec<Addr> {
        self.participation
            .iter()
            .filter_map(|(worker, participated)| {
                Threshold::try_from((*participated, self.event_count))
                    .ok()
                    .filter(|participation| participation >= &self.params.participation_threshold)
                    .map(|_| Addr::unchecked(worker)) // Ok to convert unchecked here, since we only store valid addresses
            })
            .collect()
    }
}

#[cw_serde]
pub struct Event {
    pub event_id: nonempty::String,
    pub contract: Addr,
    pub epoch_num: u64,
}

impl Event {
    pub fn new(event_id: nonempty::String, contract: Addr, epoch_num: u64) -> Self {
        Self {
            event_id,
            contract,
            epoch_num,
        }
    }
}

#[cw_serde]
pub struct Epoch {
    pub epoch_num: u64,
    pub block_height_started: u64,
}

#[cw_serde]
pub struct RewardsPool {
    pub contract: Addr,
    pub balance: Uint128,
}

impl RewardsPool {
    #[allow(dead_code)]
    pub fn new(contract: Addr) -> Self {
        RewardsPool {
            contract,
            balance: Uint128::zero(),
        }
    }

    pub fn distribute_rewards(
        &mut self,
        worker_count: u64,
        rewards_per_worker: Uint128,
    ) -> Result<(), ContractError> {
        let rewards = rewards_per_worker * Uint128::from(worker_count as u128);
        if self.balance < rewards {
            return Err(ContractError::PoolBalanceInsufficient.into());
        }
        self.balance -= rewards;
        Ok(())
    }
}

#[automock]
pub trait Store {
    fn load_params(&self) -> StoredParams;

    fn load_rewards_watermark(&self, contract: Addr) -> Result<Option<u64>, ContractError>;

    fn load_event(&self, event_id: String, contract: Addr) -> Result<Option<Event>, ContractError>;

    fn load_epoch_tally(
        &self,
        contract: Addr,
        epoch_num: u64,
    ) -> Result<Option<EpochTally>, ContractError>;

    fn load_rewards_pool(&self, contract: Addr) -> Result<Option<RewardsPool>, ContractError>;

    fn save_params(&mut self, params: &StoredParams) -> Result<(), ContractError>;

    fn save_rewards_watermark(
        &mut self,
        contract: Addr,
        epoch_num: u64,
    ) -> Result<(), ContractError>;

    fn save_event(&mut self, event: &Event) -> Result<(), ContractError>;

    fn save_epoch_tally(&mut self, tally: &EpochTally) -> Result<(), ContractError>;

    fn save_rewards_pool(&mut self, pool: &RewardsPool) -> Result<(), ContractError>;
}

/// Current rewards parameters, along with when the params were updated
pub const PARAMS: Item<StoredParams> = Item::new("params");

/// Maps a (contract address, epoch number) pair to a tally for that epoch and contract
const TALLIES: Map<(Addr, u64), EpochTally> = Map::new("tallies");

/// Maps an (event id, contract address) pair to an Event
const EVENTS: Map<(String, Addr), Event> = Map::new("events");

/// Maps a contract address to the rewards pool for that contract
const POOLS: Map<Addr, RewardsPool> = Map::new("pools");

/// Maps a contract address to the epoch number of the most recent epoch for which rewards were distributed. All epochs prior
/// have had rewards distributed already and all epochs after have not yet had rewards distributed for this contract
const WATERMARKS: Map<Addr, u64> = Map::new("rewards_watermarks");

pub const CONFIG: Item<Config> = Item::new("config");

pub struct RewardsStore<'a> {
    pub storage: &'a mut dyn Storage,
}

impl Store for RewardsStore<'_> {
    fn load_params(&self) -> StoredParams {
        PARAMS.load(self.storage).expect("params should exist")
    }

    fn load_rewards_watermark(&self, contract: Addr) -> Result<Option<u64>, ContractError> {
        WATERMARKS
            .may_load(self.storage, contract)
            .change_context(ContractError::LoadRewardsWatermark)
    }

    fn load_event(&self, event_id: String, contract: Addr) -> Result<Option<Event>, ContractError> {
        EVENTS
            .may_load(self.storage, (event_id, contract))
            .change_context(ContractError::LoadEvent)
    }

    fn load_epoch_tally(
        &self,
        contract: Addr,
        epoch_num: u64,
    ) -> Result<Option<EpochTally>, ContractError> {
        TALLIES
            .may_load(self.storage, (contract, epoch_num))
            .change_context(ContractError::LoadEpochTally)
    }

    fn load_rewards_pool(&self, contract: Addr) -> Result<Option<RewardsPool>, ContractError> {
        POOLS
            .may_load(self.storage, contract)
            .change_context(ContractError::LoadRewardsPool)
    }

    fn save_params(&mut self, params: &StoredParams) -> Result<(), ContractError> {
        PARAMS
            .save(self.storage, params)
            .change_context(ContractError::SaveParams)
    }

    fn save_rewards_watermark(
        &mut self,
        contract: Addr,
        epoch_num: u64,
    ) -> Result<(), ContractError> {
        WATERMARKS
            .save(self.storage, contract, &epoch_num)
            .change_context(ContractError::SaveRewardsWatermark)
    }

    fn save_event(&mut self, event: &Event) -> Result<(), ContractError> {
        EVENTS
            .save(
                self.storage,
                (event.event_id.clone().into(), event.contract.clone()),
                event,
            )
            .change_context(ContractError::SaveEvent)
    }

    fn save_epoch_tally(&mut self, tally: &EpochTally) -> Result<(), ContractError> {
        TALLIES
            .save(
                self.storage,
                (tally.contract.clone(), tally.epoch.epoch_num),
                tally,
            )
            .change_context(ContractError::SaveEpochTally)
    }

    fn save_rewards_pool(&mut self, pool: &RewardsPool) -> Result<(), ContractError> {
        POOLS
            .save(self.storage, pool.contract.clone(), pool)
            .change_context(ContractError::SaveRewardsPool)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use cosmwasm_std::{testing::mock_dependencies, Addr, Uint128, Uint64};

    use crate::{error::ContractError, msg::Params, state::StoredParams};

    use super::{Epoch, EpochTally, Event, RewardsPool, RewardsStore, Store};

    /// Tests that only workers that participated in a fraction of events greater than or equal to participation threshold are rewarded
    #[test]
    fn epoch_tally_workers_to_reward() {
        let tally = EpochTally {
            params: Params {
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_per_epoch: Uint128::one().try_into().unwrap(),
                participation_threshold: (1, 2).try_into().unwrap(),
            },
            contract: Addr::unchecked("worker contract"),
            event_count: 101u64,
            participation: HashMap::from([
                ("worker1".into(), 75u64),
                ("worker2".into(), 50u64),
                ("worker3".into(), 51u64),
            ]),
            epoch: Epoch {
                epoch_num: 1u64,
                block_height_started: 0u64,
            },
        };
        let workers = tally.workers_to_reward();
        assert_eq!(workers.len(), 2);
        assert!(workers.contains(&Addr::unchecked("worker1")));
        assert!(workers.contains(&Addr::unchecked("worker3")));
    }

    #[test]
    fn rewards_pool_distribute_rewards() {
        let mut pool = RewardsPool {
            contract: Addr::unchecked("worker contract"),
            balance: Uint128::from(100u128),
        };
        let worker_count = 10;
        let rewards_per_worker = 5u128;
        pool.distribute_rewards(worker_count, Uint128::from(rewards_per_worker))
            .unwrap();
        assert_eq!(pool.balance, Uint128::from(50u128));
    }

    #[test]
    fn rewards_pool_distribute_rewards_low_balance() {
        let mut pool = RewardsPool {
            contract: Addr::unchecked("worker contract"),
            balance: Uint128::from(100u128),
        };
        let worker_count = 10;
        let rewards_per_worker = 100u128;
        let err = pool
            .distribute_rewards(worker_count, Uint128::from(rewards_per_worker))
            .unwrap_err();
        assert_eq!(
            err.current_context(),
            &ContractError::PoolBalanceInsufficient
        );
    }

    #[test]
    fn save_and_load_params() {
        let mut mock_deps = mock_dependencies();
        let mut store = RewardsStore {
            storage: &mut mock_deps.storage,
        };
        let params = StoredParams {
            params: Params {
                participation_threshold: (Uint64::new(1), Uint64::new(2)).try_into().unwrap(),
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_per_epoch: Uint128::from(1000u128).try_into().unwrap(),
            },
            last_updated: Epoch {
                epoch_num: 1,
                block_height_started: 1,
            },
        };
        // save an initial params, then load it
        assert!(store.save_params(&params).is_ok());
        let loaded = store.load_params();
        assert_eq!(loaded, params);

        // now store a new params, and check that it was updated
        let new_params = StoredParams {
            params: Params {
                epoch_duration: 200u64.try_into().unwrap(),
                ..params.params
            },
            last_updated: Epoch {
                epoch_num: 2,
                block_height_started: 101,
            },
        };
        assert!(store.save_params(&new_params).is_ok());
        let loaded = store.load_params();
        assert_eq!(loaded, new_params);
    }

    #[test]
    fn save_and_load_rewards_watermark() {
        let mut mock_deps = mock_dependencies();
        let mut store = RewardsStore {
            storage: &mut mock_deps.storage,
        };
        let epoch = Epoch {
            epoch_num: 10,
            block_height_started: 1000,
        };
        let contract = Addr::unchecked("some contract");

        // should be empty at first
        let loaded = store.load_rewards_watermark(contract.clone());
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // save the first water mark
        let res = store.save_rewards_watermark(contract.clone(), epoch.epoch_num);
        assert!(res.is_ok());

        let loaded = store.load_rewards_watermark(contract.clone());
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), epoch.epoch_num);

        // now store a new watermark, should overwrite
        let res = store.save_rewards_watermark(contract.clone(), epoch.epoch_num + 1);
        assert!(res.is_ok());

        let loaded = store.load_rewards_watermark(contract);
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), epoch.epoch_num + 1);

        // check different contract
        let diff_contract = Addr::unchecked("some other contract");
        // should be empty at first
        let loaded = store.load_rewards_watermark(diff_contract.clone());
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // save the first water mark for this contract
        let res = store.save_rewards_watermark(diff_contract.clone(), epoch.epoch_num + 7);
        assert!(res.is_ok());

        let loaded = store.load_rewards_watermark(diff_contract.clone());
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), epoch.epoch_num + 7);
    }

    #[test]
    fn save_and_load_event() {
        let mut mock_deps = mock_dependencies();
        let mut store = RewardsStore {
            storage: &mut mock_deps.storage,
        };

        let event = Event {
            contract: Addr::unchecked("some contract"),
            event_id: "some event".try_into().unwrap(),
            epoch_num: 2,
        };

        let res = store.save_event(&event);
        assert!(res.is_ok());

        // check that we load the event that we just saved
        let loaded = store.load_event(event.event_id.clone().into(), event.contract.clone());
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), event);

        // different event id and contract address should return none
        let loaded = store.load_event(
            "some other event".into(),
            Addr::unchecked("different contract"),
        );
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // same event id but different contract address, should still return none
        let loaded = store.load_event(
            event.event_id.clone().into(),
            Addr::unchecked("different contract"),
        );
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // different event id, but same contract address, should still return none
        let loaded = store.load_event("some other event".into(), event.contract);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());
    }

    #[test]
    fn save_and_load_epoch_tally() {
        let mut mock_deps = mock_dependencies();
        let mut store = RewardsStore {
            storage: &mut mock_deps.storage,
        };

        let epoch_num = 10;
        let contract = Addr::unchecked("some contract");
        let rewards_rate = Uint128::from(100u128).try_into().unwrap();
        let epoch = Epoch {
            epoch_num,
            block_height_started: 1,
        };
        let mut tally = EpochTally::new(
            contract.clone(),
            epoch,
            Params {
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_per_epoch: rewards_rate,
                participation_threshold: (1, 2).try_into().unwrap(),
            },
        );

        tally = tally.record_participation(Addr::unchecked("worker"));

        let res = store.save_epoch_tally(&tally);
        assert!(res.is_ok());

        // check that we load the tally that we just saved
        let loaded = store.load_epoch_tally(contract.clone(), epoch_num);
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), tally);

        // different contract but same epoch should return none
        let loaded = store.load_epoch_tally(Addr::unchecked("different contract"), epoch_num);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // different epoch but same contract should return none
        let loaded = store.load_epoch_tally(contract.clone(), epoch_num + 1);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // different epoch and different contract should return none
        let loaded = store.load_epoch_tally(contract.clone(), epoch_num + 1);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());
    }

    #[test]
    fn save_and_load_rewards_pool() {
        let mut mock_deps = mock_dependencies();
        let mut store = RewardsStore {
            storage: &mut mock_deps.storage,
        };

        let contract = Addr::unchecked("some contract");
        let pool = RewardsPool::new(contract.clone());
        let res = store.save_rewards_pool(&pool);
        assert!(res.is_ok());

        let loaded = store.load_rewards_pool(contract);

        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), pool);

        let loaded = store.load_rewards_pool(Addr::unchecked("a different contract"));
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_none());
    }
}

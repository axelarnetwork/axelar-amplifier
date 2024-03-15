use std::collections::HashMap;
use std::ops::Deref;

use axelar_wasm_std::{nonempty, Threshold};
use connection_router_api::ChainName;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdResult, Storage, Uint128};
use cw_storage_plus::{Item, Key, KeyDeserialize, Map, Prefixer, PrimaryKey};
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

/// PoolId a unique identifier for a rewards pool
#[cw_serde]
#[derive(Eq, Hash)]
pub struct PoolId {
    pub chain_name: ChainName,
    pub contract: Addr,
}

impl PrimaryKey<'_> for PoolId {
    type Prefix = ChainName;
    type SubPrefix = ();
    type Suffix = Addr;
    type SuperSuffix = (ChainName, Addr);

    fn key(&self) -> Vec<Key> {
        let mut keys = self.chain_name.key();
        keys.extend(self.contract.key());
        keys
    }
}

impl KeyDeserialize for PoolId {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let (chain_name, contract) = <(ChainName, Addr)>::from_vec(value)?;
        Ok(PoolId {
            chain_name,
            contract,
        })
    }
}

impl<'a> Prefixer<'a> for PoolId {
    fn prefix(&self) -> Vec<Key> {
        self.key()
    }
}

#[cw_serde]
#[derive(Eq, Hash)]
pub struct TallyId {
    pub pool_id: PoolId,
    pub epoch_num: u64,
}

impl PrimaryKey<'_> for TallyId {
    type Prefix = PoolId;
    type SubPrefix = ();
    type Suffix = ();
    type SuperSuffix = (PoolId, u64);

    fn key(&self) -> Vec<Key> {
        let mut keys = self.pool_id.key();
        keys.extend(self.epoch_num.key());
        keys
    }
}

impl KeyDeserialize for TallyId {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        let (pool_id, epoch_num) = <(PoolId, u64)>::from_vec(value)?;
        Ok(TallyId { pool_id, epoch_num })
    }
}

#[cw_serde]
pub struct EpochTally {
    pub pool_id: PoolId,
    pub event_count: u64,
    pub participation: HashMap<String, u64>, // maps a worker address to participation count. Can't use Addr as key else deserialization will fail
    pub epoch: Epoch,
    pub params: Params,
}

impl EpochTally {
    pub fn new(pool_id: PoolId, epoch: Epoch, params: Params) -> Self {
        EpochTally {
            pool_id,
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
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        self
    }

    pub fn rewards_by_worker(&self) -> HashMap<Addr, Uint128> {
        let workers_to_reward = self.workers_to_reward();
        let total_rewards: Uint128 = self.params.rewards_per_epoch.into();

        let rewards_per_worker = total_rewards
            .checked_div(Uint128::from(workers_to_reward.len() as u128))
            .unwrap_or_default();

        // A bit of a weird case. The rewards per epoch is too low to accommodate the number of workers to be rewarded
        // This can't be checked when setting the rewards per epoch, as the number of workers to be rewarded is not known at that time.
        if rewards_per_worker.is_zero() {
            return HashMap::new();
        }

        workers_to_reward
            .into_iter()
            .map(|worker| (worker, rewards_per_worker))
            .collect()
    }

    fn workers_to_reward(&self) -> Vec<Addr> {
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
    pub pool_id: PoolId,
    pub epoch_num: u64,
}

impl Event {
    pub fn new(event_id: nonempty::String, pool_id: PoolId, epoch_num: u64) -> Self {
        Self {
            event_id,
            pool_id,
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
    pub id: PoolId,
    pub balance: Uint128,
}

impl RewardsPool {
    #[allow(dead_code)]
    pub fn new(chain_name: ChainName, contract: Addr) -> Self {
        RewardsPool {
            id: PoolId {
                chain_name,
                contract,
            },
            balance: Uint128::zero(),
        }
    }

    pub fn sub_reward(mut self, reward: Uint128) -> Result<Self, ContractError> {
        self.balance = self
            .balance
            .checked_sub(reward)
            .map_err(|_| ContractError::PoolBalanceInsufficient)?;

        Ok(self)
    }
}

#[automock]
pub trait Store {
    fn load_params(&self) -> StoredParams;

    fn load_rewards_watermark(&self, pool_id: PoolId) -> Result<Option<u64>, ContractError>;

    fn load_event(&self, event_id: String, pool_id: PoolId)
        -> Result<Option<Event>, ContractError>;

    fn load_epoch_tally(
        &self,
        pool_id: PoolId,
        epoch_num: u64,
    ) -> Result<Option<EpochTally>, ContractError>;

    fn load_rewards_pool(&self, pool_id: PoolId) -> Result<RewardsPool, ContractError>;

    fn save_params(&mut self, params: &StoredParams) -> Result<(), ContractError>;

    fn save_rewards_watermark(
        &mut self,
        pool_id: PoolId,
        epoch_num: u64,
    ) -> Result<(), ContractError>;

    fn save_event(&mut self, event: &Event) -> Result<(), ContractError>;

    fn save_epoch_tally(&mut self, tally: &EpochTally) -> Result<(), ContractError>;

    fn save_rewards_pool(&mut self, pool: &RewardsPool) -> Result<(), ContractError>;
}

/// Current rewards parameters, along with when the params were updated
pub const PARAMS: Item<StoredParams> = Item::new("params");

/// Maps a (pool id, epoch number) pair to a tally for that epoch and rewards pool
const TALLIES: Map<TallyId, EpochTally> = Map::new("tallies");

/// Maps an (event id, pool id) pair to an Event
const EVENTS: Map<(String, PoolId), Event> = Map::new("events");

/// Maps the id to the rewards pool for given chain and contract
const POOLS: Map<PoolId, RewardsPool> = Map::new("pools");

/// Maps a rewards pool to the epoch number of the most recent epoch for which rewards were distributed. All epochs prior
/// have had rewards distributed already and all epochs after have not yet had rewards distributed for this pool
const WATERMARKS: Map<PoolId, u64> = Map::new("rewards_watermarks");

pub const CONFIG: Item<Config> = Item::new("config");

pub struct RewardsStore<'a> {
    pub storage: &'a mut dyn Storage,
}

impl Store for RewardsStore<'_> {
    fn load_params(&self) -> StoredParams {
        PARAMS.load(self.storage).expect("params should exist")
    }

    fn load_rewards_watermark(&self, pool_id: PoolId) -> Result<Option<u64>, ContractError> {
        WATERMARKS
            .may_load(self.storage, pool_id)
            .change_context(ContractError::LoadRewardsWatermark)
    }

    fn load_event(
        &self,
        event_id: String,
        pool_id: PoolId,
    ) -> Result<Option<Event>, ContractError> {
        EVENTS
            .may_load(self.storage, (event_id, pool_id))
            .change_context(ContractError::LoadEvent)
    }

    fn load_epoch_tally(
        &self,
        pool_id: PoolId,
        epoch_num: u64,
    ) -> Result<Option<EpochTally>, ContractError> {
        TALLIES
            .may_load(self.storage, TallyId { pool_id, epoch_num })
            .change_context(ContractError::LoadEpochTally)
    }

    fn load_rewards_pool(&self, pool_id: PoolId) -> Result<RewardsPool, ContractError> {
        POOLS
            .may_load(self.storage, pool_id.clone())
            .change_context(ContractError::LoadRewardsPool)
            .map(|pool| {
                pool.unwrap_or(RewardsPool {
                    id: pool_id,
                    balance: Uint128::zero(),
                })
            })
    }

    fn save_params(&mut self, params: &StoredParams) -> Result<(), ContractError> {
        PARAMS
            .save(self.storage, params)
            .change_context(ContractError::SaveParams)
    }

    fn save_rewards_watermark(
        &mut self,
        pool_id: PoolId,
        epoch_num: u64,
    ) -> Result<(), ContractError> {
        WATERMARKS
            .save(self.storage, pool_id, &epoch_num)
            .change_context(ContractError::SaveRewardsWatermark)
    }

    fn save_event(&mut self, event: &Event) -> Result<(), ContractError> {
        EVENTS
            .save(
                self.storage,
                (event.event_id.clone().into(), event.pool_id.clone()),
                event,
            )
            .change_context(ContractError::SaveEvent)
    }

    fn save_epoch_tally(&mut self, tally: &EpochTally) -> Result<(), ContractError> {
        let tally_id = TallyId {
            pool_id: tally.pool_id.clone(),
            epoch_num: tally.epoch.epoch_num,
        };

        TALLIES
            .save(self.storage, tally_id, tally)
            .change_context(ContractError::SaveEpochTally)
    }

    fn save_rewards_pool(&mut self, pool: &RewardsPool) -> Result<(), ContractError> {
        POOLS
            .save(self.storage, pool.id.clone(), pool)
            .change_context(ContractError::SaveRewardsPool)
    }
}

pub(crate) enum StorageState<T> {
    Existing(T),
    New(T),
}

impl<T> Deref for StorageState<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            StorageState::Existing(value) => value,
            StorageState::New(value) => value,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Epoch, EpochTally, Event, PoolId, RewardsPool, RewardsStore, Store};
    use crate::error::ContractError;
    use crate::{msg::Params, state::StoredParams};
    use connection_router_api::ChainName;
    use cosmwasm_std::{testing::mock_dependencies, Addr, Uint128, Uint64};
    use std::collections::HashMap;

    /// Test that the rewards are
    /// - distributed evenly to all workers that reach quorum
    /// - no rewards if there are no workers
    /// - no rewards if rewards per epoch is too low for number of workers
    #[test]
    fn rewards_by_worker() {
        let tally = EpochTally {
            params: Params {
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_per_epoch: Uint128::new(1000).try_into().unwrap(),
                participation_threshold: (1, 2).try_into().unwrap(),
            },
            pool_id: PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("worker contract"),
            },
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

        let test_cases = vec![
            (
                // distribute rewards evenly to all workers that reach quorum
                tally.clone(),
                HashMap::from([
                    (Addr::unchecked("worker1"), Uint128::from(500u128)),
                    (Addr::unchecked("worker3"), Uint128::from(500u128)),
                ]),
            ),
            (
                // no rewards if there are no workers
                EpochTally {
                    participation: HashMap::new(),
                    ..tally.clone()
                },
                HashMap::new(),
            ),
            (
                // no rewards if rewards per epoch is too low for number of workers
                EpochTally {
                    params: Params {
                        rewards_per_epoch: Uint128::one().try_into().unwrap(),
                        ..tally.params
                    },
                    ..tally
                },
                HashMap::new(),
            ),
        ];

        for test_case in test_cases {
            let rewards = test_case.0.rewards_by_worker();
            assert_eq!(rewards, test_case.1);
        }
    }

    #[test]
    fn sub_reward_from_pool() {
        let pool = RewardsPool {
            id: PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("worker contract"),
            },
            balance: Uint128::from(100u128),
        };
        let new_pool = pool.sub_reward(Uint128::from(50u128)).unwrap();
        assert_eq!(new_pool.balance, Uint128::from(50u128));

        let new_pool = new_pool.sub_reward(Uint128::from(60u128));
        assert!(matches!(
            new_pool.unwrap_err().current_context(),
            ContractError::PoolBalanceInsufficient
        ));
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
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };

        // should be empty at first
        let loaded = store.load_rewards_watermark(pool_id.clone());
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // save the first watermark
        let res = store.save_rewards_watermark(pool_id.clone(), epoch.epoch_num);
        assert!(res.is_ok());

        let loaded = store.load_rewards_watermark(pool_id.clone());
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), epoch.epoch_num);

        // now store a new watermark, should overwrite
        let res = store.save_rewards_watermark(pool_id.clone(), epoch.epoch_num + 1);
        assert!(res.is_ok());

        let loaded = store.load_rewards_watermark(pool_id);
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), epoch.epoch_num + 1);

        // check different contract
        let diff_pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some other contract"),
        };
        // should be empty at first
        let loaded = store.load_rewards_watermark(diff_pool_id.clone());
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // save the first watermark for this contract
        let res = store.save_rewards_watermark(diff_pool_id.clone(), epoch.epoch_num + 7);
        assert!(res.is_ok());

        let loaded = store.load_rewards_watermark(diff_pool_id.clone());
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
            pool_id: PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("some contract"),
            },
            event_id: "some event".try_into().unwrap(),
            epoch_num: 2,
        };

        let res = store.save_event(&event);
        assert!(res.is_ok());

        // check that we load the event that we just saved
        let loaded = store.load_event(event.event_id.clone().into(), event.pool_id.clone());
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), event);

        // different event id and contract address should return none
        let diff_pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("different contract"),
        };
        let loaded = store.load_event("some other event".into(), diff_pool_id.clone());
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // same event id but different contract address, should still return none
        let loaded = store.load_event(event.event_id.clone().into(), diff_pool_id);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // different event id, but same contract address, should still return none
        let loaded = store.load_event("some other event".into(), event.pool_id);
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
        let rewards_rate = Uint128::from(100u128).try_into().unwrap();
        let epoch = Epoch {
            epoch_num,
            block_height_started: 1,
        };
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };
        let mut tally = EpochTally::new(
            pool_id.clone(),
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
        let loaded = store.load_epoch_tally(pool_id.clone(), epoch_num);
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), tally);

        // different contract but same epoch should return none
        let loaded = store.load_epoch_tally(
            PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("different contract"),
            },
            epoch_num,
        );
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // different epoch but same contract should return none
        let loaded = store.load_epoch_tally(pool_id.clone(), epoch_num + 1);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // different epoch and different contract should return none
        let loaded = store.load_epoch_tally(pool_id.clone(), epoch_num + 1);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());
    }

    #[test]
    fn save_and_load_rewards_pool() {
        let mut mock_deps = mock_dependencies();
        let mut store = RewardsStore {
            storage: &mut mock_deps.storage,
        };

        let chain_name: ChainName = "mock-chain".parse().unwrap();
        let pool = RewardsPool::new(chain_name.clone(), Addr::unchecked("some contract"));
        let res = store.save_rewards_pool(&pool);
        assert!(res.is_ok());

        let loaded = store.load_rewards_pool(pool.id.clone());

        assert!(loaded.is_ok());
        assert_eq!(loaded.unwrap(), pool);

        let loaded = store.load_rewards_pool(PoolId {
            chain_name: chain_name.clone(),
            contract: Addr::unchecked("a different contract"),
        });
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().balance.is_zero());
    }
}

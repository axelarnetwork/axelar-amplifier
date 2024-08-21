use std::collections::HashMap;
use std::ops::Deref;

use axelar_wasm_std::{nonempty, Threshold};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdResult, Storage, Uint128};
use cw_storage_plus::{Item, Key, KeyDeserialize, Map, Prefixer, PrimaryKey};
use error_stack::{Result, ResultExt};
use router_api::ChainName;

use crate::error::ContractError;
use crate::msg::Params;

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

#[cw_serde]
pub struct Config {
    pub rewards_denom: String,
}

#[cw_serde]
pub struct ParamsSnapshot {
    pub params: Params,
    /// epoch in which the params were updated
    pub created_at: Epoch,
}

/// PoolId a unique identifier for a rewards pool
#[cw_serde]
#[derive(Eq, Hash)]
pub struct PoolId {
    pub chain_name: ChainName,
    pub contract: Addr,
}

impl PoolId {
    pub fn new(chain_name: ChainName, contract: Addr) -> Self {
        PoolId {
            chain_name,
            contract,
        }
    }
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
    pub participation: HashMap<String, u64>, // maps a verifier address to participation count. Can't use Addr as key else deserialization will fail
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

    /// IMPORTANT: verifier address must be validated before calling this function
    /// TODO: panic if address is invalid?
    pub fn record_participation(mut self, verifier: Addr) -> Self {
        self.participation
            .entry(verifier.to_string())
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        self
    }

    pub fn rewards_by_verifier(&self) -> HashMap<Addr, Uint128> {
        let verifiers_to_reward = self.verifiers_to_reward();
        let total_rewards: Uint128 = self.params.rewards_per_epoch.into();

        let rewards_per_verifier = total_rewards
            .checked_div(Uint128::from(verifiers_to_reward.len() as u128))
            .unwrap_or_default();

        // A bit of a weird case. The rewards per epoch is too low to accommodate the number of verifiers to be rewarded
        // This can't be checked when setting the rewards per epoch, as the number of verifiers to be rewarded is not known at that time.
        if rewards_per_verifier.is_zero() {
            return HashMap::new();
        }

        verifiers_to_reward
            .into_iter()
            .map(|verifier| (verifier, rewards_per_verifier))
            .collect()
    }

    fn verifiers_to_reward(&self) -> Vec<Addr> {
        self.participation
            .iter()
            .filter_map(|(verifier, participated)| {
                Threshold::try_from((*participated, self.event_count))
                    .ok()
                    .filter(|participation| participation >= &self.params.participation_threshold)
                    .map(|_| Addr::unchecked(verifier)) // Ok to convert unchecked here, since we only store valid addresses
            })
            .collect()
    }

    pub fn verifier_participation(&self) -> HashMap<Addr, u64> {
        self.participation
            .iter()
            .map(|(verifier, participation)| (Addr::unchecked(verifier), *participation)) // Ok to convert unchecked here, since we only store valid addresses
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

impl Epoch {
    /// Returns the current epoch. The current epoch is computed dynamically based on the current
    /// block height and the epoch duration. If the epoch duration is updated, we store the epoch
    /// in which the update occurs as the last checkpoint
    pub fn current(
        current_params: &ParamsSnapshot,
        cur_block_height: u64,
    ) -> Result<Epoch, ContractError> {
        let epoch_duration: u64 = current_params.params.epoch_duration.into();
        let last_updated_epoch = &current_params.created_at;

        if cur_block_height < last_updated_epoch.block_height_started {
            Err(ContractError::BlockHeightInPast.into())
        } else {
            let epochs_elapsed = cur_block_height
                .saturating_sub(last_updated_epoch.block_height_started)
                .checked_div(epoch_duration)
                .expect("invalid invariant: epoch duration is zero");
            Ok(Epoch {
                epoch_num: last_updated_epoch
                    .epoch_num
                    .checked_add(epochs_elapsed)
                    .expect(
                        "epoch number should be strictly smaller than the current block height",
                    ),
                block_height_started: last_updated_epoch
                    .block_height_started
                    .checked_add(epochs_elapsed.saturating_mul(epoch_duration)).expect("start of current epoch should be strictly smaller than the current block height"),
            })
        }
    }
}

#[cw_serde]
pub struct RewardsPool {
    pub id: PoolId,
    pub balance: Uint128,
    pub params: ParamsSnapshot,
}

impl RewardsPool {
    pub fn sub_reward(mut self, reward: Uint128) -> Result<Self, ContractError> {
        self.balance = self
            .balance
            .checked_sub(reward)
            .map_err(|_| ContractError::PoolBalanceInsufficient)?;

        Ok(self)
    }
}

#[cw_serde]
pub struct RewardsDistribution {
    /// Amount of rewards denom each verifier received
    pub rewards: HashMap<Addr, Uint128>,
    /// List of epochs processed for this distribution
    pub epochs_processed: Vec<u64>,
    /// Epoch in which rewards were distributed
    pub current_epoch: Epoch,
    /// True if there are more rewards to distribute (later epochs that have not yet been distributed but are ready for distribution at the time of calling)
    pub can_distribute_more: bool,
}
pub fn load_config(storage: &dyn Storage) -> Config {
    CONFIG.load(storage).expect("couldn't load config")
}

pub fn load_rewards_watermark(
    storage: &dyn Storage,
    pool_id: PoolId,
) -> Result<Option<u64>, ContractError> {
    WATERMARKS
        .may_load(storage, pool_id)
        .change_context(ContractError::LoadRewardsWatermark)
}

pub fn load_event(
    storage: &dyn Storage,
    event_id: String,
    pool_id: PoolId,
) -> Result<Option<Event>, ContractError> {
    EVENTS
        .may_load(storage, (event_id, pool_id))
        .change_context(ContractError::LoadEvent)
}

pub fn load_epoch_tally(
    storage: &dyn Storage,
    pool_id: PoolId,
    epoch_num: u64,
) -> Result<Option<EpochTally>, ContractError> {
    TALLIES
        .may_load(storage, TallyId { pool_id, epoch_num })
        .change_context(ContractError::LoadEpochTally)
}

pub fn may_load_rewards_pool(
    storage: &dyn Storage,
    pool_id: PoolId,
) -> Result<Option<RewardsPool>, ContractError> {
    POOLS
        .may_load(storage, pool_id.clone())
        .change_context(ContractError::LoadRewardsPool)
}

pub fn load_rewards_pool(
    storage: &dyn Storage,
    pool_id: PoolId,
) -> Result<RewardsPool, ContractError> {
    may_load_rewards_pool(storage, pool_id.clone())?
        .ok_or(ContractError::RewardsPoolNotFound.into())
}

pub fn load_rewards_pool_params(
    storage: &dyn Storage,
    pool_id: PoolId,
) -> Result<ParamsSnapshot, ContractError> {
    may_load_rewards_pool(storage, pool_id.clone())?
        .ok_or(ContractError::RewardsPoolNotFound.into())
        .map(|pool| pool.params)
}

pub fn save_rewards_watermark(
    storage: &mut dyn Storage,
    pool_id: PoolId,
    epoch_num: u64,
) -> Result<(), ContractError> {
    WATERMARKS
        .save(storage, pool_id, &epoch_num)
        .change_context(ContractError::SaveRewardsWatermark)
}

pub fn save_event(storage: &mut dyn Storage, event: &Event) -> Result<(), ContractError> {
    EVENTS
        .save(
            storage,
            (event.event_id.clone().into(), event.pool_id.clone()),
            event,
        )
        .change_context(ContractError::SaveEvent)
}

pub fn save_epoch_tally(
    storage: &mut dyn Storage,
    tally: &EpochTally,
) -> Result<(), ContractError> {
    let tally_id = TallyId {
        pool_id: tally.pool_id.clone(),
        epoch_num: tally.epoch.epoch_num,
    };

    TALLIES
        .save(storage, tally_id, tally)
        .change_context(ContractError::SaveEpochTally)
}

pub fn save_rewards_pool(
    storage: &mut dyn Storage,
    pool: &RewardsPool,
) -> Result<(), ContractError> {
    POOLS
        .save(storage, pool.id.clone(), pool)
        .change_context(ContractError::SaveRewardsPool)
}

pub fn update_pool_params(
    storage: &mut dyn Storage,
    pool_id: &PoolId,
    updated_params: &ParamsSnapshot,
) -> Result<RewardsPool, ContractError> {
    POOLS
        .update(storage, pool_id.clone(), |pool| match pool {
            None => Err(ContractError::RewardsPoolNotFound),
            Some(pool) => Ok(RewardsPool {
                id: pool_id.to_owned(),
                balance: pool.balance,
                params: updated_params.to_owned(),
            }),
        })
        .change_context(ContractError::UpdateRewardsPool)
}

pub fn pool_exists(storage: &mut dyn Storage, pool_id: &PoolId) -> Result<bool, ContractError> {
    POOLS
        .may_load(storage, pool_id.to_owned())
        .change_context(ContractError::LoadRewardsPool)
        .map(|pool| pool.is_some())
}

pub fn current_epoch(
    storage: &mut dyn Storage,
    pool_id: &PoolId,
    cur_block_height: u64,
) -> Result<Epoch, ContractError> {
    Epoch::current(
        &load_rewards_pool_params(storage, pool_id.to_owned())?,
        cur_block_height,
    )
}

pub enum StorageState<T> {
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
    use std::collections::HashMap;

    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{Addr, Uint128, Uint64};
    use router_api::ChainName;

    use super::*;
    use crate::error::ContractError;
    use crate::msg::Params;
    use crate::state::ParamsSnapshot;

    /// Test that the rewards are
    /// - distributed evenly to all verifiers that reach quorum
    /// - no rewards if there are no verifiers
    /// - no rewards if rewards per epoch is too low for number of verifiers
    #[test]
    fn rewards_by_verifier() {
        let tally = EpochTally {
            params: Params {
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_per_epoch: Uint128::new(1000).try_into().unwrap(),
                participation_threshold: (1, 2).try_into().unwrap(),
            },
            pool_id: PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("pool_contract"),
            },
            event_count: 101u64,
            participation: HashMap::from([
                ("verifier1".into(), 75u64),
                ("verifier2".into(), 50u64),
                ("verifier3".into(), 51u64),
            ]),
            epoch: Epoch {
                epoch_num: 1u64,
                block_height_started: 0u64,
            },
        };

        let test_cases = vec![
            (
                // distribute rewards evenly to all verifiers that reach quorum
                tally.clone(),
                HashMap::from([
                    (Addr::unchecked("verifier1"), Uint128::from(500u128)),
                    (Addr::unchecked("verifier3"), Uint128::from(500u128)),
                ]),
            ),
            (
                // no rewards if there are no verifiers
                EpochTally {
                    participation: HashMap::new(),
                    ..tally.clone()
                },
                HashMap::new(),
            ),
            (
                // no rewards if rewards per epoch is too low for number of verifiers
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
            let rewards = test_case.0.rewards_by_verifier();
            assert_eq!(rewards, test_case.1);
        }
    }

    #[test]
    fn sub_reward_from_pool() {
        let params = ParamsSnapshot {
            params: Params {
                participation_threshold: (Uint64::new(1), Uint64::new(2)).try_into().unwrap(),
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_per_epoch: Uint128::from(1000u128).try_into().unwrap(),
            },
            created_at: Epoch {
                epoch_num: 1,
                block_height_started: 1,
            },
        };
        let pool = RewardsPool {
            id: PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("pool_contract"),
            },
            balance: Uint128::from(100u128),
            params,
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
    fn save_and_load_rewards_watermark() {
        let mut mock_deps = mock_dependencies();
        let epoch = Epoch {
            epoch_num: 10,
            block_height_started: 1000,
        };
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };

        // should be empty at first
        let loaded = load_rewards_watermark(mock_deps.as_ref().storage, pool_id.clone());
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // save the first watermark
        let res =
            save_rewards_watermark(mock_deps.as_mut().storage, pool_id.clone(), epoch.epoch_num);
        assert!(res.is_ok());

        let loaded = load_rewards_watermark(mock_deps.as_ref().storage, pool_id.clone());
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), epoch.epoch_num);

        // now store a new watermark, should overwrite
        let res = save_rewards_watermark(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            epoch.epoch_num + 1,
        );
        assert!(res.is_ok());

        let loaded = load_rewards_watermark(mock_deps.as_ref().storage, pool_id);
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), epoch.epoch_num + 1);

        // check different contract
        let diff_pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some other contract"),
        };
        // should be empty at first
        let loaded = load_rewards_watermark(mock_deps.as_ref().storage, diff_pool_id.clone());
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // save the first watermark for this contract
        let res = save_rewards_watermark(
            mock_deps.as_mut().storage,
            diff_pool_id.clone(),
            epoch.epoch_num + 7,
        );
        assert!(res.is_ok());

        let loaded = load_rewards_watermark(mock_deps.as_ref().storage, diff_pool_id.clone());
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), epoch.epoch_num + 7);
    }

    #[test]
    fn save_and_load_event() {
        let mut mock_deps = mock_dependencies();

        let event = Event {
            pool_id: PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("some contract"),
            },
            event_id: "some event".try_into().unwrap(),
            epoch_num: 2,
        };

        let res = save_event(mock_deps.as_mut().storage, &event);
        assert!(res.is_ok());

        // check that we load the event that we just saved
        let loaded = load_event(
            mock_deps.as_ref().storage,
            event.event_id.clone().into(),
            event.pool_id.clone(),
        );
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), event);

        // different event id and contract address should return none
        let diff_pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("different contract"),
        };
        let loaded = load_event(
            mock_deps.as_ref().storage,
            "some other event".into(),
            diff_pool_id.clone(),
        );
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // same event id but different contract address, should still return none
        let loaded = load_event(
            mock_deps.as_ref().storage,
            event.event_id.clone().into(),
            diff_pool_id,
        );
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // different event id, but same contract address, should still return none
        let loaded = load_event(
            mock_deps.as_ref().storage,
            "some other event".into(),
            event.pool_id,
        );
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());
    }

    #[test]
    fn save_and_load_epoch_tally() {
        let mut mock_deps = mock_dependencies();

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

        tally = tally.record_participation(Addr::unchecked("verifier"));

        let res = save_epoch_tally(mock_deps.as_mut().storage, &tally);
        assert!(res.is_ok());

        // check that we load the tally that we just saved
        let loaded = load_epoch_tally(mock_deps.as_ref().storage, pool_id.clone(), epoch_num);
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), tally);

        // different contract but same epoch should return none
        let loaded = load_epoch_tally(
            mock_deps.as_ref().storage,
            PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("different contract"),
            },
            epoch_num,
        );
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // different epoch but same contract should return none
        let loaded = load_epoch_tally(mock_deps.as_ref().storage, pool_id.clone(), epoch_num + 1);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // different epoch and different contract should return none
        let loaded = load_epoch_tally(mock_deps.as_ref().storage, pool_id.clone(), epoch_num + 1);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());
    }

    #[test]
    fn save_and_load_rewards_pool() {
        let params = ParamsSnapshot {
            params: Params {
                participation_threshold: (Uint64::new(1), Uint64::new(2)).try_into().unwrap(),
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_per_epoch: Uint128::from(1000u128).try_into().unwrap(),
            },
            created_at: Epoch {
                epoch_num: 1,
                block_height_started: 1,
            },
        };
        let mut mock_deps = mock_dependencies();

        let chain_name: ChainName = "mock-chain".parse().unwrap();
        let pool = RewardsPool {
            id: PoolId::new(chain_name.clone(), Addr::unchecked("some contract")),
            params,
            balance: Uint128::zero(),
        };
        let res = save_rewards_pool(mock_deps.as_mut().storage, &pool);
        assert!(res.is_ok());

        let loaded = load_rewards_pool(mock_deps.as_ref().storage, pool.id.clone());

        assert!(loaded.is_ok());
        assert_eq!(loaded.unwrap(), pool);
    }
}

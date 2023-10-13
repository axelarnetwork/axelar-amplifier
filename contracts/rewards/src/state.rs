use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage, Uint256};
use cw_storage_plus::{Item, Map};
use error_stack::{Result, ResultExt};

use crate::{error::ContractError, msg::RewardsParams};

#[cw_serde]
pub struct StoredParams {
    pub params: RewardsParams,
    /// epoch in which the params were updated
    pub updated: Epoch,
}

#[cw_serde]
pub struct EpochTally {
    pub epoch_num: u64,
    pub contract: Addr,
    pub event_count: u64,
    pub participation: HashMap<Addr, u64>,
    pub rewards_rate: Uint256,
}

impl EpochTally {
    #[allow(dead_code)]
    pub fn new(epoch_num: u64, contract: Addr, rewards_rate: Uint256) -> Self {
        EpochTally {
            epoch_num,
            contract,
            event_count: 0,
            participation: HashMap::new(),
            rewards_rate,
        }
    }
}

#[cw_serde]
pub struct Event {
    event_id: String,
    contract: Addr,
    epoch_num: u64,
}

#[cw_serde]
pub struct Epoch {
    pub epoch_num: u64,
    pub block_height_started: u64,
}

#[cw_serde]
pub struct RewardsPool {
    contract: Addr,
    balance: Uint256,
}

impl RewardsPool {
    #[allow(dead_code)]
    pub fn new(contract: Addr) -> Self {
        RewardsPool {
            contract,
            balance: Uint256::zero(),
        }
    }
}

pub trait Store {
    fn load_params(&self) -> StoredParams;

    fn load_rewards_watermark(&self) -> Result<Option<u64>, ContractError>;

    fn load_event(&self, event_id: String, contract: Addr) -> Result<Option<Event>, ContractError>;

    fn load_epoch_tally(
        &self,
        contract: Addr,
        epoch_num: u64,
    ) -> Result<Option<EpochTally>, ContractError>;

    fn load_rewards_pool(&self, contract: Addr) -> Result<Option<RewardsPool>, ContractError>;

    fn save_params(&mut self, params: &StoredParams) -> Result<(), ContractError>;

    fn save_rewards_watermark(&mut self, epoch_num: u64) -> Result<(), ContractError>;

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

/// Epoch number of the most recent epoch for which rewards were distributed. All epochs prior
/// have had rewards distributed already and all epochs after have not yet had rewards distributed.
const WATERMARK: Item<u64> = Item::new("rewards_watermark");

pub struct RewardsStore<'a> {
    pub storage: &'a mut dyn Storage,
}

impl Store for RewardsStore<'_> {
    fn load_params(&self) -> StoredParams {
        PARAMS.load(self.storage).expect("params should exist")
    }

    fn load_rewards_watermark(&self) -> Result<Option<u64>, ContractError> {
        WATERMARK
            .may_load(self.storage)
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

    fn save_rewards_watermark(&mut self, epoch_num: u64) -> Result<(), ContractError> {
        WATERMARK
            .save(self.storage, &epoch_num)
            .change_context(ContractError::SaveRewardsWatermark)
    }

    fn save_event(&mut self, event: &Event) -> Result<(), ContractError> {
        EVENTS
            .save(
                self.storage,
                (event.event_id.clone(), event.contract.clone()),
                event,
            )
            .change_context(ContractError::SaveEvent)
    }

    fn save_epoch_tally(&mut self, tally: &EpochTally) -> Result<(), ContractError> {
        TALLIES
            .save(
                self.storage,
                (tally.contract.clone(), tally.epoch_num),
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
    use cosmwasm_std::{testing::mock_dependencies, Addr, Uint256, Uint64};

    use crate::{msg::RewardsParams, state::StoredParams};

    use super::{Epoch, EpochTally, Event, RewardsPool, RewardsStore, Store};

    #[test]
    fn save_and_load_params() {
        let mut mock_deps = mock_dependencies();
        let mut store = RewardsStore {
            storage: &mut mock_deps.storage,
        };
        let params = StoredParams {
            params: RewardsParams {
                participation_threshold: (Uint64::new(1), Uint64::new(2)).try_into().unwrap(),
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_rate: Uint256::from(1000u128).try_into().unwrap(),
            },
            updated: Epoch {
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
            params: RewardsParams {
                epoch_duration: 200u64.try_into().unwrap(),
                ..params.params
            },
            updated: Epoch {
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

        // should be empty at first
        let loaded = store.load_rewards_watermark();
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_none());

        // save the first water mark
        let res = store.save_rewards_watermark(epoch.epoch_num);
        assert!(res.is_ok());

        let loaded = store.load_rewards_watermark();
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), epoch.epoch_num);

        // now store a new watermark, should overwrite
        let res = store.save_rewards_watermark(epoch.epoch_num + 1);
        assert!(res.is_ok());

        let loaded = store.load_rewards_watermark();
        assert!(loaded.is_ok());
        assert!(loaded.as_ref().unwrap().is_some());
        assert_eq!(loaded.unwrap().unwrap(), epoch.epoch_num + 1);
    }

    #[test]
    fn save_and_load_event() {
        let mut mock_deps = mock_dependencies();
        let mut store = RewardsStore {
            storage: &mut mock_deps.storage,
        };

        let event = Event {
            contract: Addr::unchecked("some contract"),
            event_id: "some event".into(),
            epoch_num: 2,
        };

        let res = store.save_event(&event);
        assert!(res.is_ok());

        // check that we load the event that we just saved
        let loaded = store.load_event(event.event_id.clone(), event.contract.clone());
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
            event.event_id.clone(),
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
        let rewards_rate = Uint256::from(100u128).try_into().unwrap();
        let tally = EpochTally::new(epoch_num, contract.clone(), rewards_rate);

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

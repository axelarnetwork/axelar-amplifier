use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage, Uint256};
use cw_storage_plus::{Item, Map};

use crate::{error::ContractError, msg::RewardsParams};

#[cw_serde]
pub struct Config {
    pub params: RewardsParams,
}

#[cw_serde]
pub struct EpochTally {
    epoch_num: u64,
    contract: Addr,
    total_events: u64,
    participation: HashMap<Addr, u64>,
    distributed_rewards: bool,
}

impl EpochTally {
    #[allow(dead_code)]
    pub fn new(epoch_num: u64, contract: Addr) -> Self {
        EpochTally {
            epoch_num,
            contract,
            total_events: 0,
            participation: HashMap::new(),
            distributed_rewards: false,
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
    epoch_num: u64,
    block_height_started: u64,
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
    fn load_config(&self) -> Config;

    fn load_current_epoch(&self) -> Result<Epoch, ContractError>;

    fn load_event(&self, event_id: String, contract: Addr) -> Result<Option<Event>, ContractError>;

    fn load_epoch_tally(
        &self,
        contract: Addr,
        epoch_num: u64,
    ) -> Result<Option<EpochTally>, ContractError>;

    fn load_rewards_pool(&self, contract: Addr) -> Result<Option<RewardsPool>, ContractError>;

    fn save_config(&mut self, config: &Config) -> Result<(), ContractError>;

    fn save_current_epoch(&mut self, epoch: &Epoch) -> Result<(), ContractError>;

    fn save_event(&mut self, event: &Event) -> Result<(), ContractError>;

    fn save_epoch_tally(&mut self, tally: &EpochTally) -> Result<(), ContractError>;

    fn save_rewards_pool(&mut self, pool: &RewardsPool) -> Result<(), ContractError>;
}

pub const CONFIG: Item<Config> = Item::new("config");

const CURRENT_EPOCH: Item<Epoch> = Item::new("current_epoch");

const TALLIES: Map<(Addr, u64), EpochTally> = Map::new("tallies");

const EVENTS: Map<(String, Addr), Event> = Map::new("events");

const POOLS: Map<Addr, RewardsPool> = Map::new("pools");

pub struct RewardsStore<'a> {
    pub storage: &'a mut dyn Storage,
}

impl Store for RewardsStore<'_> {
    fn load_config(&self) -> Config {
        CONFIG
            .load(self.storage)
            .expect("config should be set during contract instantiation")
    }

    fn load_current_epoch(&self) -> Result<Epoch, ContractError> {
        Ok(CURRENT_EPOCH.load(self.storage)?)
    }

    fn load_event(&self, event_id: String, contract: Addr) -> Result<Option<Event>, ContractError> {
        Ok(EVENTS.may_load(self.storage, (event_id, contract))?)
    }

    fn load_epoch_tally(
        &self,
        contract: Addr,
        epoch_num: u64,
    ) -> Result<Option<EpochTally>, ContractError> {
        Ok(TALLIES.may_load(self.storage, (contract, epoch_num))?)
    }

    fn load_rewards_pool(&self, contract: Addr) -> Result<Option<RewardsPool>, ContractError> {
        Ok(POOLS.may_load(self.storage, contract)?)
    }

    fn save_config(&mut self, config: &Config) -> Result<(), ContractError> {
        Ok(CONFIG.save(self.storage, config)?)
    }

    fn save_current_epoch(&mut self, epoch: &Epoch) -> Result<(), ContractError> {
        Ok(CURRENT_EPOCH.save(self.storage, epoch)?)
    }

    fn save_event(&mut self, event: &Event) -> Result<(), ContractError> {
        Ok(EVENTS.save(
            self.storage,
            (event.event_id.clone(), event.contract.clone()),
            event,
        )?)
    }

    fn save_epoch_tally(&mut self, tally: &EpochTally) -> Result<(), ContractError> {
        Ok(TALLIES.save(
            self.storage,
            (tally.contract.clone(), tally.epoch_num),
            tally,
        )?)
    }

    fn save_rewards_pool(&mut self, pool: &RewardsPool) -> Result<(), ContractError> {
        Ok(POOLS.save(self.storage, pool.contract.clone(), pool)?)
    }
}

#[cfg(test)]
mod test {
    use cosmwasm_std::{testing::mock_dependencies, Addr, Uint256, Uint64};

    use crate::{msg::RewardsParams, state::Config};

    use super::{Epoch, EpochTally, Event, RewardsPool, RewardsStore, Store};

    #[test]
    fn save_and_load_config() {
        let mut mock_deps = mock_dependencies();
        let mut store = RewardsStore {
            storage: &mut mock_deps.storage,
        };
        let config = Config {
            params: RewardsParams {
                participation_threshold: (Uint64::new(1), Uint64::new(2)).try_into().unwrap(),
                epoch_duration: 100u64.try_into().unwrap(),
                rewards_rate: Uint256::from(1000u128).try_into().unwrap(),
            },
        };
        // save an initial config, then load it
        assert!(store.save_config(&config).is_ok());
        let loaded = store.load_config();
        assert_eq!(loaded, config);

        // now store a new config, and check that it was updated
        let new_config = Config {
            params: RewardsParams {
                epoch_duration: 200u64.try_into().unwrap(),
                ..config.params
            },
        };
        assert!(store.save_config(&new_config).is_ok());
        let loaded = store.load_config();
        assert_eq!(loaded, new_config);
    }

    #[test]
    fn save_and_load_current_epoch() {
        let mut mock_deps = mock_dependencies();
        let mut store = RewardsStore {
            storage: &mut mock_deps.storage,
        };
        let epoch = Epoch {
            epoch_num: 10,
            block_height_started: 1000,
        };
        // save the first current epoch
        let res = store.save_current_epoch(&epoch);
        assert!(res.is_ok());

        let loaded = store.load_current_epoch();
        assert!(loaded.is_ok());
        assert_eq!(loaded.unwrap(), epoch);

        // now store a new epoch and load it
        let new_epoch = Epoch {
            epoch_num: 11,
            block_height_started: 2000,
        };

        let res = store.save_current_epoch(&new_epoch);
        assert!(res.is_ok());

        let loaded = store.load_current_epoch();
        assert!(loaded.is_ok());
        assert_eq!(loaded.unwrap(), new_epoch);
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
        let tally = EpochTally::new(epoch_num, contract.clone());

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

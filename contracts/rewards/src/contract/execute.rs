use error_stack::Result;
use std::collections::HashMap;

use axelar_wasm_std::nonempty;
use cosmwasm_std::{Addr, Uint256};

use crate::{
    error::ContractError,
    msg::RewardsParams,
    state::{Epoch, EpochTally, Event, Store},
};

pub struct Contract<S>
where
    S: Store,
{
    pub store: S,
}

#[allow(dead_code)]
impl<S> Contract<S>
where
    S: Store,
{
    /// Returns the current epoch. The current epoch is computed dynamically based on the current
    /// block height and the epoch duration. If the epoch duration is updated, we store the epoch
    /// in which the update occurs as the last checkpoint
    fn get_current_epoch(&self, cur_block_height: u64) -> Result<Epoch, ContractError> {
        let stored_params = self.store.load_params();
        let epoch_duration: u64 = stored_params.params.epoch_duration.into();
        let epoch = stored_params.last_updated;
        if cur_block_height >= epoch.block_height_started + epoch_duration {
            let epochs_elapsed = (cur_block_height - epoch.block_height_started) / epoch_duration;
            let epoch_num = epochs_elapsed + epoch.epoch_num;
            let block_height_started = epoch.block_height_started + epochs_elapsed * epoch_duration;

            let new_epoch = Epoch {
                epoch_num,
                block_height_started,
                rewards: epoch.rewards,
            };
            return Ok(new_epoch);
        }
        Ok(epoch)
    }

    pub fn record_participation(
        &mut self,
        event_id: nonempty::String,
        worker: Addr,
        contract_addr: Addr,
        block_height: u64,
    ) -> Result<(), ContractError> {
        let cur_epoch = self.get_current_epoch(block_height)?;

        let event = self
            .store
            .load_event(event_id.to_string(), contract_addr.clone())?;

        if event.is_none() {
            self.store.save_event(&Event::new(
                event_id,
                contract_addr.clone(),
                cur_epoch.epoch_num,
            ))?;
        }

        let tally = match event {
            Some(event) => self
                .store
                .load_epoch_tally(contract_addr.clone(), event.epoch_num)?
                .expect("couldn't find epoch tally for existing event"),
            None => self
                .store
                .load_epoch_tally(contract_addr.clone(), cur_epoch.epoch_num)?
                .unwrap_or(EpochTally::new(contract_addr, cur_epoch)) // first event in this epoch
                .increment_event_count(),
        }
        .record_participation(worker);

        self.store.save_epoch_tally(&tally)?;

        Ok(())
    }

    pub fn process_rewards(
        &mut self,
        _contract: Addr,
        _block_height: u64,
        _count: Option<u64>,
    ) -> Result<HashMap<Addr, Uint256>, ContractError> {
        todo!()
    }

    pub fn update_params(
        &mut self,
        _new_params: RewardsParams,
        _block_height: u64,
    ) -> Result<(), ContractError> {
        todo!()
    }

    pub fn add_rewards(
        &mut self,
        _contract: Addr,
        _amount: nonempty::Uint256,
        _block_height: u64,
    ) -> Result<(), ContractError> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };

    use axelar_wasm_std::nonempty;
    use cosmwasm_std::{Addr, Uint256, Uint64};

    use crate::{
        msg::RewardsParams,
        state::{self, Epoch, EpochTally, Event, Store, StoredParams},
    };

    use super::Contract;

    /// Tests that the current epoch is computed correctly when the expected epoch is the same as the stored epoch
    #[test]
    fn get_current_epoch_same_epoch_is_idempotent() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let contract = setup(cur_epoch_num, block_height_started, epoch_duration);
        let new_epoch = contract.get_current_epoch(block_height_started).unwrap();
        assert_eq!(new_epoch.epoch_num, cur_epoch_num);
        assert_eq!(new_epoch.block_height_started, block_height_started);

        let new_epoch = contract
            .get_current_epoch(block_height_started + 1)
            .unwrap();
        assert_eq!(new_epoch.epoch_num, cur_epoch_num);
        assert_eq!(new_epoch.block_height_started, block_height_started);

        let new_epoch = contract
            .get_current_epoch(block_height_started + epoch_duration - 1)
            .unwrap();
        assert_eq!(new_epoch.epoch_num, cur_epoch_num);
        assert_eq!(new_epoch.block_height_started, block_height_started);
    }

    /// Tests that the current epoch is computed correctly when the expected epoch is different than the stored epoch
    #[test]
    fn get_current_epoch_different_epoch() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let contract = setup(cur_epoch_num, block_height_started, epoch_duration);

        // elements are (height, expected epoch number, expected epoch start)
        let test_cases = vec![
            (
                block_height_started + epoch_duration,
                cur_epoch_num + 1,
                block_height_started + epoch_duration,
            ),
            (
                block_height_started + epoch_duration + epoch_duration / 2,
                cur_epoch_num + 1,
                block_height_started + epoch_duration,
            ),
            (
                block_height_started + epoch_duration * 4,
                cur_epoch_num + 4,
                block_height_started + epoch_duration * 4,
            ),
            (
                block_height_started + epoch_duration * 4 + epoch_duration / 2,
                cur_epoch_num + 4,
                block_height_started + epoch_duration * 4,
            ),
        ];

        for (height, expected_epoch_num, expected_block_start) in test_cases {
            let new_epoch = contract.get_current_epoch(height).unwrap();

            assert_eq!(new_epoch.epoch_num, expected_epoch_num);
            assert_eq!(new_epoch.block_height_started, expected_block_start);
        }
    }

    /// Tests that multiple participation events for the same contract within a given epoch are recorded correctly
    #[test]
    fn record_participation_multiple_events() {
        let cur_epoch_num = 1u64;
        let epoch_block_start = 250u64;
        let epoch_duration = 100u64;
        let event_store = Arc::new(RwLock::new(HashMap::new()));
        let tally_store = Arc::new(RwLock::new(HashMap::new()));

        let mut contract = setup_with_stores(
            cur_epoch_num,
            epoch_block_start,
            epoch_duration,
            event_store.clone(),
            tally_store.clone(),
        );

        let worker_contract = Addr::unchecked("some contract");

        let mut simulated_participation = HashMap::new();
        simulated_participation.insert(Addr::unchecked("worker_1"), 10);
        simulated_participation.insert(Addr::unchecked("worker_2"), 5);
        simulated_participation.insert(Addr::unchecked("worker_3"), 7);

        let event_count = 10;
        let mut cur_height = epoch_block_start;
        for i in 0..event_count {
            for (worker, part_count) in &simulated_participation {
                // simulates a worker participating in only part_count events
                if i < *part_count {
                    let event_id = i.to_string().try_into().unwrap();
                    contract
                        .record_participation(
                            event_id,
                            worker.clone(),
                            worker_contract.clone(),
                            cur_height,
                        )
                        .unwrap();
                }
            }
            cur_height = cur_height + 1;
        }

        let tally = contract
            .store
            .load_epoch_tally(worker_contract, cur_epoch_num)
            .unwrap();
        assert!(tally.is_some());

        let tally = tally.unwrap();
        assert_eq!(tally.event_count, event_count);
        assert_eq!(tally.participation.len(), simulated_participation.len());
        for (worker, part_count) in simulated_participation {
            assert_eq!(tally.participation.get(&worker), Some(&part_count));
        }
    }

    /// Tests that the participation event is recorded correctly when the event spans multiple epochs
    #[test]
    fn record_participation_epoch_boundary() {
        let starting_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let event_store = Arc::new(RwLock::new(HashMap::new()));
        let tally_store = Arc::new(RwLock::new(HashMap::new()));

        let mut contract = setup_with_stores(
            starting_epoch_num,
            block_height_started,
            epoch_duration,
            event_store.clone(),
            tally_store.clone(),
        );

        let worker_contract = Addr::unchecked("some contract");

        let workers = vec![
            Addr::unchecked("worker_1"),
            Addr::unchecked("worker_2"),
            Addr::unchecked("worker_3"),
        ];
        // this is the height just before the next epoch starts
        let height_at_epoch_end = block_height_started + epoch_duration - 1;
        // workers participate in consecutive blocks
        for (i, workers) in workers.iter().enumerate() {
            contract
                .record_participation(
                    "some event".to_string().try_into().unwrap(),
                    workers.clone(),
                    worker_contract.clone(),
                    height_at_epoch_end + i as u64,
                )
                .unwrap();
        }

        let cur_epoch = contract.get_current_epoch(height_at_epoch_end).unwrap();
        assert_ne!(starting_epoch_num + 1, cur_epoch.epoch_num);

        let tally = contract
            .store
            .load_epoch_tally(worker_contract.clone(), starting_epoch_num)
            .unwrap();
        assert!(tally.is_some());

        let tally = tally.unwrap();

        assert_eq!(tally.event_count, 1);
        assert_eq!(tally.participation.len(), workers.len());
        for w in workers {
            assert_eq!(tally.participation.get(&w), Some(&1));
        }

        let tally = contract
            .store
            .load_epoch_tally(worker_contract, starting_epoch_num + 1)
            .unwrap();
        assert!(tally.is_none());
    }

    /// Tests that participation events for different contracts are recorded correctly
    #[test]
    fn record_participation_multiple_contracts() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let event_store = Arc::new(RwLock::new(HashMap::new()));
        let tally_store = Arc::new(RwLock::new(HashMap::new()));

        let mut contract = setup_with_stores(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            event_store.clone(),
            tally_store.clone(),
        );

        let mut simulated_participation = HashMap::new();
        simulated_participation.insert(
            Addr::unchecked("worker_1"),
            (Addr::unchecked("contract_1"), 3),
        );
        simulated_participation.insert(
            Addr::unchecked("worker_2"),
            (Addr::unchecked("contract_2"), 4),
        );
        simulated_participation.insert(
            Addr::unchecked("worker_3"),
            (Addr::unchecked("contract_3"), 2),
        );

        for (worker, (worker_contract, events_participated)) in &simulated_participation {
            for i in 0..*events_participated {
                let event_id = i.to_string().try_into().unwrap();
                contract
                    .record_participation(
                        event_id,
                        worker.clone(),
                        worker_contract.clone(),
                        block_height_started,
                    )
                    .unwrap();
            }
        }

        for (worker, (worker_contract, events_participated)) in simulated_participation {
            let tally = contract
                .store
                .load_epoch_tally(worker_contract.clone(), cur_epoch_num)
                .unwrap();

            assert!(tally.is_some());
            let tally = tally.unwrap();

            assert_eq!(tally.event_count, events_participated);
            assert_eq!(tally.participation.len(), 1);
            assert_eq!(tally.participation.get(&worker), Some(&events_participated));
        }
    }

    fn create_contract(
        stored_params: StoredParams,
        events_store: Arc<RwLock<HashMap<(String, Addr), Event>>>,
        tally_store: Arc<RwLock<HashMap<(Addr, u64), EpochTally>>>,
    ) -> Contract<state::MockStore> {
        let mut store = state::MockStore::new();
        store
            .expect_load_params()
            .returning(move || stored_params.clone());
        let events_store_cloned = events_store.clone();
        store.expect_load_event().returning(move |id, contract| {
            let events_store = events_store_cloned.read().unwrap();
            Ok(events_store.get(&(id, contract)).cloned())
        });
        store.expect_save_event().returning(move |event| {
            let mut events_store = events_store.write().unwrap();
            events_store.insert(
                (event.event_id.clone().into(), event.contract.clone()),
                event.clone(),
            );
            Ok(())
        });
        let tally_store_cloned = tally_store.clone();
        store
            .expect_load_epoch_tally()
            .returning(move |contract, epoch_num| {
                let tally_store = tally_store_cloned.read().unwrap();
                Ok(tally_store.get(&(contract, epoch_num)).cloned())
            });
        store.expect_save_epoch_tally().returning(move |tally| {
            let mut tally_store = tally_store.write().unwrap();
            tally_store.insert(
                (tally.contract.clone(), tally.epoch.epoch_num.clone()),
                tally.clone(),
            );
            Ok(())
        });
        Contract { store }
    }

    fn setup_with_stores(
        cur_epoch_num: u64,
        block_height_started: u64,
        epoch_duration: u64,
        events_store: Arc<RwLock<HashMap<(String, Addr), Event>>>,
        tally_store: Arc<RwLock<HashMap<(Addr, u64), EpochTally>>>,
    ) -> Contract<state::MockStore> {
        let rewards_per_epoch: nonempty::Uint256 = Uint256::from(100u128).try_into().unwrap();
        let current_epoch = Epoch {
            epoch_num: cur_epoch_num,
            block_height_started,
            rewards: rewards_per_epoch.clone(),
        };

        let stored_params = StoredParams {
            params: RewardsParams {
                participation_threshold: (Uint64::new(1), Uint64::new(2)).try_into().unwrap(),
                epoch_duration: epoch_duration.try_into().unwrap(),
                rewards_per_epoch,
            },
            last_updated: current_epoch.clone(),
        };

        create_contract(stored_params.clone(), events_store, tally_store)
    }

    fn setup(
        cur_epoch_num: u64,
        block_height_started: u64,
        epoch_duration: u64,
    ) -> Contract<state::MockStore> {
        let events_store = Arc::new(RwLock::new(HashMap::new()));
        let tally_store = Arc::new(RwLock::new(HashMap::new()));
        setup_with_stores(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            events_store,
            tally_store,
        )
    }
}

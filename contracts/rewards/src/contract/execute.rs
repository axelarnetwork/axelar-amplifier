use std::collections::HashMap;

use axelar_wasm_std::nonempty::Uint256;
use cosmwasm_std::Addr;

use crate::{
    error::ContractError,
    msg::RewardsParams,
    state::{Epoch, RewardsPool, Store},
};

use error_stack::Result;

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
        _event_id: String,
        _worker: Addr,
        _contract: Addr,
        _block_height: u64,
    ) -> Result<(), ContractError> {
        todo!()
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

    pub fn add_rewards(&mut self, contract: Addr, amount: Uint256) -> Result<(), ContractError> {
        let pool = self.store.load_rewards_pool(contract.clone())?;

        let updated_pool = match pool {
            Some(pool) => RewardsPool {
                balance: pool.balance + cosmwasm_std::Uint256::from(amount),
                ..pool
            },
            None => RewardsPool {
                contract,
                balance: amount.into(),
            },
        };

        self.store.save_rewards_pool(&updated_pool)?;

        Ok(())
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
        state::{self, Epoch, RewardsPool, Store, StoredParams},
    };

    use super::Contract;

    /// Tests that the current epoch is computed correctly when the expected epoch is the same as the stored epoch
    #[test]
    fn get_current_epoch_same_epoch_is_idempotent() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let mut contract = setup(cur_epoch_num, block_height_started, epoch_duration);
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

    /// Tests that rewards are added correctly to a single contract
    #[test]
    fn add_rewards() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let rewards_store = Arc::new(RwLock::new(HashMap::new()));

        let mut contract = setup_with_stores(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            rewards_store,
        );
        let worker_contract = Addr::unchecked("some contract");
        let pool = contract
            .store
            .load_rewards_pool(worker_contract.clone())
            .unwrap();
        assert!(pool.is_none());

        let initial_amount = Uint256::from(100u128);
        contract
            .add_rewards(worker_contract.clone(), initial_amount.try_into().unwrap())
            .unwrap();

        let pool = contract
            .store
            .load_rewards_pool(worker_contract.clone())
            .unwrap();
        assert!(pool.is_some());
        assert_eq!(pool.unwrap().balance, initial_amount);

        let added_amount = Uint256::from(500u128);
        contract
            .add_rewards(worker_contract.clone(), added_amount.try_into().unwrap())
            .unwrap();

        let pool = contract
            .store
            .load_rewards_pool(worker_contract)
            .unwrap()
            .unwrap();
        assert_eq!(pool.balance, initial_amount + added_amount);
    }

    /// Tests that rewards are added correctly with multiple contracts
    #[test]
    fn add_rewards_multiple_contracts() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let rewards_store = Arc::new(RwLock::new(HashMap::new()));

        let mut contract = setup_with_stores(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            rewards_store,
        );
        // a vector of (worker contract, rewards amounts) pairs
        let test_data = vec![
            (Addr::unchecked("contract_1"), vec![100, 200, 50]),
            (Addr::unchecked("contract_2"), vec![25, 500, 70]),
            (Addr::unchecked("contract_3"), vec![1000, 500, 2000]),
        ];

        for (worker_contract, rewards) in &test_data {
            for amount in rewards {
                contract
                    .add_rewards(
                        worker_contract.clone(),
                        cosmwasm_std::Uint256::from(*amount as u128)
                            .try_into()
                            .unwrap(),
                    )
                    .unwrap();
            }
        }

        for (worker_contract, rewards) in test_data {
            let pool = contract
                .store
                .load_rewards_pool(worker_contract)
                .unwrap()
                .unwrap();
            assert_eq!(
                pool.balance,
                cosmwasm_std::Uint256::from(rewards.iter().sum::<u128>())
            );
        }
    }

    fn create_contract(
        stored_params: StoredParams,
        rewards_store: Arc<RwLock<HashMap<Addr, RewardsPool>>>,
    ) -> Contract<state::MockStore> {
        let mut store = state::MockStore::new();
        store
            .expect_load_params()
            .returning(move || stored_params.clone());

        let rewards_store_cloned = rewards_store.clone();
        store.expect_load_rewards_pool().returning(move |contract| {
            let rewards_store = rewards_store_cloned.read().unwrap();
            Ok(rewards_store.get(&contract).cloned())
        });
        store.expect_save_rewards_pool().returning(move |pool| {
            let mut rewards_store = rewards_store.write().unwrap();
            rewards_store.insert(pool.contract.clone(), pool.clone());
            Ok(())
        });
        Contract { store }
    }

    fn setup_with_stores(
        cur_epoch_num: u64,
        block_height_started: u64,
        epoch_duration: u64,
        rewards_store: Arc<RwLock<HashMap<Addr, RewardsPool>>>,
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

        create_contract(stored_params.clone(), rewards_store)
    }

    fn setup(
        cur_epoch_num: u64,
        block_height_started: u64,
        epoch_duration: u64,
    ) -> Contract<state::MockStore> {
        let rewards_store = Arc::new(RwLock::new(HashMap::new()));
        setup_with_stores(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            rewards_store,
        )
    }
}

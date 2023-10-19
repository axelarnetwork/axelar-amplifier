use error_stack::Result;
use std::collections::HashMap;

use axelar_wasm_std::nonempty::Uint256;
use cosmwasm_std::Addr;

use crate::{
    error::ContractError,
    msg::RewardsParams,
    state::{Epoch, Store, StoredParams},
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
        new_params: RewardsParams,
        block_height: u64,
    ) -> Result<(), ContractError> {
        let mut cur_epoch = self.get_current_epoch(block_height)?;
        // If the param update reduces the epoch duration such that the current epoch immediately ends,
        // start a new epoch at this block, incrementing the current epoch number by 1.
        // This prevents us from jumping forward an arbitrary number of epochs, and maintains consistency for past events.
        // (i.e. we are in epoch 0, which started at block 0 and epoch duration is 1000. At epoch 500, the params
        // are updated to shorten the epoch duration to 100 blocks. We set the epoch number to 1, to prevent skipping
        // epochs 1-4, and so all events prior to the start of epoch 1 have an epoch number of 0)
        if cur_epoch.block_height_started + u64::from(new_params.epoch_duration) < block_height {
            cur_epoch = Epoch {
                block_height_started: block_height,
                epoch_num: cur_epoch.epoch_num + 1,
                rewards: new_params.rewards_per_epoch,
            };
        } else {
            cur_epoch.rewards = new_params.rewards_per_epoch;
        }
        self.store.save_params(&StoredParams {
            params: new_params,
            last_updated: cur_epoch,
        })?;
        Ok(())
    }

    pub fn add_rewards(
        &mut self,
        _contract: Addr,
        _amount: Uint256,
        _block_height: u64,
    ) -> Result<(), ContractError> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, RwLock};

    use axelar_wasm_std::nonempty;
    use cosmwasm_std::Uint64;

    use crate::{
        msg::RewardsParams,
        state::{self, Epoch, Store, StoredParams},
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

    /// Test that rewards parameters are updated correctly. In this test we don't change the epoch duration, so
    /// that computation of the current epoch is unaffected.
    #[test]
    fn update_params() {
        let initial_epoch_num = 1u64;
        let initial_epoch_start = 250u64;
        let initial_rewards_per_epoch = 100u128;
        let initial_participation_threshold = (1, 2);
        let epoch_duration = 100u64;
        let mut contract = setup_with_params(
            initial_epoch_num,
            initial_epoch_start,
            epoch_duration,
            initial_rewards_per_epoch,
            initial_participation_threshold,
        );

        // simulate the below tests running at this block height
        let cur_height = initial_epoch_start + epoch_duration * 10 + 2;

        let new_params = RewardsParams {
            rewards_per_epoch: cosmwasm_std::Uint256::from(initial_rewards_per_epoch + 100)
                .try_into()
                .unwrap(),
            participation_threshold: (Uint64::new(2), Uint64::new(3)).try_into().unwrap(),
            epoch_duration: epoch_duration.try_into().unwrap(), // keep this the same to not affect epoch computation
        };

        // the epoch shouldn't change when the params are updated, since we are not changing the epoch duration
        let expected_epoch = contract.get_current_epoch(cur_height).unwrap();

        contract
            .update_params(new_params.clone(), cur_height)
            .unwrap();
        let stored = contract.store.load_params();
        assert_eq!(stored.params, new_params);

        // current epoch shouldn't have changed
        let cur_epoch = contract.get_current_epoch(cur_height).unwrap();
        assert_eq!(expected_epoch.epoch_num, cur_epoch.epoch_num);
        assert_eq!(
            expected_epoch.block_height_started,
            cur_epoch.block_height_started
        );

        // last updated should be the current epoch
        assert_eq!(stored.last_updated, cur_epoch);
    }

    /// Test extending the epoch duration. This should not change the current epoch
    #[test]
    fn extend_epoch_duration() {
        let initial_epoch_num = 1u64;
        let initial_epoch_start = 250u64;
        let initial_epoch_duration = 100u64;
        let mut contract = setup(
            initial_epoch_num,
            initial_epoch_start,
            initial_epoch_duration,
        );

        // simulate the tests running after 5 epochs have passed
        let epochs_elapsed = 5;
        let cur_height = initial_epoch_start + initial_epoch_duration * epochs_elapsed + 10; // add 10 here just to be a little past the epoch boundary

        // epoch shouldn't change if we are extending the duration
        let epoch_prior_to_update = contract.get_current_epoch(cur_height).unwrap();

        let new_epoch_duration = initial_epoch_duration * 2;
        let new_params = RewardsParams {
            epoch_duration: (new_epoch_duration).try_into().unwrap(),
            ..contract.store.load_params().params // keep everything besides epoch duration the same
        };

        contract
            .update_params(new_params.clone(), cur_height)
            .unwrap();

        // current epoch shouldn't change
        let epoch = contract.get_current_epoch(cur_height).unwrap();
        assert_eq!(epoch, epoch_prior_to_update);

        // we increased the epoch duration, so adding the initial epoch duration should leave us in the same epoch
        let epoch = contract
            .get_current_epoch(cur_height + initial_epoch_duration)
            .unwrap();
        assert_eq!(epoch, epoch_prior_to_update);

        // check that we can correctly compute the start of the next epoch
        let next_epoch = contract
            .get_current_epoch(cur_height + new_epoch_duration)
            .unwrap();
        assert_eq!(next_epoch.epoch_num, epoch_prior_to_update.epoch_num + 1);
        assert_eq!(
            next_epoch.block_height_started,
            epoch_prior_to_update.block_height_started + new_epoch_duration
        );
    }

    /// Test shortening the epoch duration. This test shortens the epoch duration such that the current epoch doesn't change
    /// (i.e. we are 10 blocks into the epoch, and we shorten the duration from 100 to 50)
    #[test]
    fn shorten_epoch_duration_same_epoch() {
        let initial_epoch_num = 1u64;
        let initial_epoch_start = 256u64;
        let initial_epoch_duration = 100u64;
        let mut contract = setup(
            initial_epoch_num,
            initial_epoch_start,
            initial_epoch_duration,
        );

        // simulate the tests running after 10 epochs have passed
        let epochs_elapsed = 10;
        let cur_height = initial_epoch_start + initial_epoch_duration * epochs_elapsed;

        let new_epoch_duration = initial_epoch_duration / 2;
        let epoch_prior_to_update = contract.get_current_epoch(cur_height).unwrap();
        // we are shortening the epoch, but not so much it causes the epoch number to change. We want to remain in the same epoch
        assert!(cur_height - epoch_prior_to_update.block_height_started < new_epoch_duration);

        let new_params = RewardsParams {
            epoch_duration: new_epoch_duration.try_into().unwrap(),
            ..contract.store.load_params().params
        };
        contract
            .update_params(new_params.clone(), cur_height)
            .unwrap();

        // current epoch shouldn't have changed
        let epoch = contract.get_current_epoch(cur_height).unwrap();
        assert_eq!(epoch_prior_to_update, epoch);

        // adding the new epoch duration should increase the epoch number by 1
        let epoch = contract
            .get_current_epoch(cur_height + new_epoch_duration)
            .unwrap();
        assert_eq!(epoch.epoch_num, epoch_prior_to_update.epoch_num + 1);
        assert_eq!(
            epoch.block_height_started,
            epoch_prior_to_update.block_height_started + new_epoch_duration
        );
    }

    /// Tests shortening the epoch duration such that the current epoch does change
    /// (i.e. we are 50 blocks into the epoch, and we shorten the duration to 10 blocks)
    #[test]
    fn shorten_epoch_duration_diff_epoch() {
        let initial_epoch_num = 1u64;
        let initial_epoch_start = 250u64;
        let initial_epoch_duration = 100u64;
        let mut contract = setup(
            initial_epoch_num,
            initial_epoch_start,
            initial_epoch_duration,
        );

        // simulate running the test after 100 epochs have elapsed
        let epochs_elapsed = 100;
        let new_epoch_duration = 10;

        // simulate progressing far enough into the epoch such that shortening the epoch duration would change the epoch
        let cur_height =
            initial_epoch_start + initial_epoch_duration * epochs_elapsed + new_epoch_duration * 2;
        let epoch_prior_to_update = contract.get_current_epoch(cur_height).unwrap();

        let new_params = RewardsParams {
            epoch_duration: 10.try_into().unwrap(),
            ..contract.store.load_params().params
        };
        contract
            .update_params(new_params.clone(), cur_height)
            .unwrap();

        // should be in new epoch now
        let epoch = contract.get_current_epoch(cur_height).unwrap();
        assert_eq!(epoch.epoch_num, epoch_prior_to_update.epoch_num + 1);
        assert_eq!(epoch.block_height_started, cur_height);

        // moving forward the new epoch duration # of blocks should increment the epoch
        let epoch = contract
            .get_current_epoch(cur_height + new_epoch_duration)
            .unwrap();
        assert_eq!(epoch.epoch_num, epoch_prior_to_update.epoch_num + 2);
        assert_eq!(epoch.block_height_started, cur_height + new_epoch_duration);
    }

    fn create_contract(params_store: Arc<RwLock<StoredParams>>) -> Contract<state::MockStore> {
        let mut store = state::MockStore::new();
        let params_store_cloned = params_store.clone();
        store
            .expect_load_params()
            .returning(move || params_store_cloned.read().unwrap().clone());
        store.expect_save_params().returning(move |new_params| {
            let mut params_store = params_store.write().unwrap();
            *params_store = new_params.clone();
            Ok(())
        });
        Contract { store }
    }

    fn setup_with_stores(params_store: Arc<RwLock<StoredParams>>) -> Contract<state::MockStore> {
        create_contract(params_store)
    }

    fn setup_with_params(
        cur_epoch_num: u64,
        block_height_started: u64,
        epoch_duration: u64,
        rewards_per_epoch: u128,
        participation_threshold: (u64, u64),
    ) -> Contract<state::MockStore> {
        let rewards_per_epoch: nonempty::Uint256 = cosmwasm_std::Uint256::from(rewards_per_epoch)
            .try_into()
            .unwrap();
        let current_epoch = Epoch {
            epoch_num: cur_epoch_num,
            block_height_started,
            rewards: rewards_per_epoch.clone(),
        };

        let stored_params = StoredParams {
            params: RewardsParams {
                participation_threshold: participation_threshold.try_into().unwrap(),
                epoch_duration: epoch_duration.try_into().unwrap(),
                rewards_per_epoch,
            },
            last_updated: current_epoch.clone(),
        };
        let stored_params = Arc::new(RwLock::new(stored_params));
        setup_with_stores(stored_params)
    }

    fn setup(
        cur_epoch_num: u64,
        block_height_started: u64,
        epoch_duration: u64,
    ) -> Contract<state::MockStore> {
        let participation_threshold = (1, 2);
        let rewards_per_epoch = 100u128;
        setup_with_params(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            rewards_per_epoch,
            participation_threshold,
        )
    }
}

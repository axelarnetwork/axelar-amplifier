use std::collections::HashMap;

use axelar_wasm_std::nonempty::Uint256;
use cosmwasm_std::Addr;

use crate::{
    error::ContractError,
    msg::RewardsParams,
    state::{Epoch, Store},
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
        _new_params: RewardsParams,
        _block_height: u64,
    ) -> Result<(), ContractError> {
        todo!()
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
    use axelar_wasm_std::nonempty;
    use cosmwasm_std::{Uint256, Uint64};

    use crate::{
        msg::RewardsParams,
        state::{self, Epoch, StoredParams},
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
        let mut contract = setup(cur_epoch_num, block_height_started, epoch_duration);

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

    fn create_contract(stored_params: StoredParams) -> Contract<state::MockStore> {
        let mut store = state::MockStore::new();
        store
            .expect_load_params()
            .returning(move || stored_params.clone());
        Contract { store }
    }

    fn setup(
        cur_epoch_num: u64,
        block_height_started: u64,
        epoch_duration: u64,
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

        create_contract(stored_params.clone())
    }
}

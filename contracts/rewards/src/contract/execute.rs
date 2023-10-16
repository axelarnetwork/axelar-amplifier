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
    fn get_current_epoch(&mut self, cur_block_height: u64) -> Result<Epoch, ContractError> {
        let stored_params = self.store.load_params();
        let epoch_duration: u64 = stored_params.params.epoch_duration.into();
        let epoch = stored_params.last_updated;
        if cur_block_height >= epoch.block_height_started + epoch_duration {
            let new_epoch_num = ((cur_block_height - epoch.block_height_started) / epoch_duration)
                + epoch.epoch_num;
            let new_epoch = Epoch {
                epoch_num: new_epoch_num,
                block_height_started: cur_block_height - (cur_block_height % epoch_duration),
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

    /// Tests that the current epoch is computed correctly based on block height and epoch duration
    #[test]
    fn test_get_current_epoch() {
        let epoch_duration = 100u64;
        let rewards_per_epoch: nonempty::Uint256 = Uint256::from(100u128).try_into().unwrap();
        let current_epoch = Epoch {
            epoch_num: 0,
            block_height_started: 0,
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
        let mut contract = create_contract(stored_params.clone());

        // epoch shouldn't change
        let new_epoch = contract
            .get_current_epoch(current_epoch.block_height_started + 1)
            .unwrap();
        assert_eq!(new_epoch, current_epoch);

        // epoch should increase by one
        let block =
            current_epoch.block_height_started + u64::from(stored_params.params.epoch_duration);
        let new_epoch = contract.get_current_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(
            Epoch {
                epoch_num: 1,
                block_height_started: block,
                rewards: current_epoch.rewards.clone()
            },
            new_epoch
        );

        // epoch should increase by one, but start of epoch is in the past
        let block =
            current_epoch.block_height_started + u64::from(stored_params.params.epoch_duration) + 1;
        let new_epoch = contract.get_current_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(
            Epoch {
                epoch_num: 1,
                block_height_started: block - 1,
                rewards: current_epoch.rewards.clone()
            },
            new_epoch
        );

        // epoch should increase by more than one
        let block =
            current_epoch.block_height_started + u64::from(stored_params.params.epoch_duration) * 4;
        let new_epoch = contract.get_current_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(
            Epoch {
                epoch_num: 4,
                block_height_started: block,
                rewards: current_epoch.rewards.clone()
            },
            new_epoch
        );

        // epoch should increase by more than one, but start of epoch is in the past
        let block = current_epoch.block_height_started
            + u64::from(stored_params.params.epoch_duration) * 4
            + 10;
        let new_epoch = contract.get_current_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(
            Epoch {
                epoch_num: 4,
                block_height_started: block - 10,
                rewards: current_epoch.rewards.clone()
            },
            new_epoch
        );
    }

    fn create_contract(stored_params: StoredParams) -> Contract<state::MockStore> {
        let mut store = state::MockStore::new();
        store
            .expect_load_params()
            .returning(move || stored_params.clone());
        Contract { store }
    }
}

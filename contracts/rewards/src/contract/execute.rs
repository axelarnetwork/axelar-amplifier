use std::collections::HashMap;

use axelar_wasm_std::nonempty::Uint256;
use cosmwasm_std::Addr;

use crate::{
    error::ContractError,
    msg::RewardsParams,
    state::{Config, Epoch, Store},
};

pub struct Contract<S>
where
    S: Store,
{
    pub store: S,
    pub config: Config,
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
        let epoch_duration: u64 = self.config.params.epoch_duration.into();
        let epoch = self.store.load_last_checkpoint()?;
        if cur_block_height >= epoch.block_start() + epoch_duration {
            let new_epoch_num =
                ((cur_block_height - epoch.block_start()) / epoch_duration) + epoch.epoch_num();
            let new_epoch = Epoch::new(
                new_epoch_num,
                cur_block_height - (cur_block_height % epoch_duration),
            );
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
        // if the epoch duration is changing, we need to store a new checkpoint,
        // so that way future epochs can be computed correctly
        if new_params.epoch_duration != self.config.params.epoch_duration {
            let cur_epoch = self.get_current_epoch(block_height)?;
            let last_checkpoint = self.store.load_last_checkpoint()?;
            if last_checkpoint != cur_epoch {
                self.store.save_last_checkpoint(&cur_epoch)?;
            }
        }

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
    use cosmwasm_std::{Uint256, Uint64};

    use crate::{
        msg::RewardsParams,
        state::{self, Config, Epoch},
    };

    use super::Contract;

    /// Tests that the current epoch is computed correctly based on block height and epoch duration
    #[test]
    fn test_get_current_epoch() {
        let epoch_duration = 100u64;
        let config = Config {
            params: RewardsParams {
                participation_threshold: (Uint64::new(1), Uint64::new(2)).try_into().unwrap(),
                epoch_duration: epoch_duration.try_into().unwrap(),
                rewards_rate: Uint256::from(1000u128).try_into().unwrap(),
            },
        };
        let current_epoch = Epoch::new(0, 0);
        let mut contract = create_contract(config.clone(), current_epoch.clone());

        // epoch shouldn't change
        let new_epoch = contract
            .get_current_epoch(current_epoch.block_start() + 1)
            .unwrap();
        assert_eq!(new_epoch, current_epoch);

        // epoch should increase by one
        let block = current_epoch.block_start() + u64::from(config.params.epoch_duration);
        let new_epoch = contract.get_current_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(Epoch::new(1, block), new_epoch);

        // epoch should increase by one, but start of epoch is in the past
        let block = current_epoch.block_start() + u64::from(config.params.epoch_duration) + 1;
        let new_epoch = contract.get_current_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(Epoch::new(1, block - 1), new_epoch);

        // epoch should increase by more than one
        let block = current_epoch.block_start() + u64::from(config.params.epoch_duration) * 4;
        let new_epoch = contract.get_current_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(Epoch::new(4, block), new_epoch);

        // epoch should increase by more than one, but start of epoch is in the past
        let block = current_epoch.block_start() + u64::from(config.params.epoch_duration) * 4 + 10;
        let new_epoch = contract.get_current_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(Epoch::new(4, block - 10), new_epoch);
    }

    fn create_contract(config: Config, current_epoch: Epoch) -> Contract<state::MockStore> {
        let mut store = state::MockStore::new();
        store
            .expect_load_last_checkpoint()
            .returning(move || Ok(current_epoch.clone()));
        store.expect_save_last_checkpoint().returning(|_| Ok(()));
        Contract { store, config }
    }
}

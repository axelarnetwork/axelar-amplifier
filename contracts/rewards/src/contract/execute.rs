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
    /// Updates internal state to the latest epoch based on current block height, and returns the latest epoch.
    /// If the computed epoch is the same as what's stored, the function returns what is stored and doesn't change
    /// the internal state.
    /// Note, the stored epoch can increase by more than one, depending on when this is called. For example,
    /// suppose we start epoch 0 at block 0, and the epoch duration is 100 blocks. If the next time this function
    /// is called is block 500 (due to no activity on the contract), then the stored epoch will jump from 0 to 5.
    /// This should be called before any operation on the contract, to ensure the correct epoch is being used. This
    /// allows lazy computation of the epoch, and removes the need to call this at any regular interval
    fn update_epoch(&mut self, cur_block_height: u64) -> Result<Epoch, ContractError> {
        let epoch_duration: u64 = self.config.params.epoch_duration.into();
        let epoch = self.store.load_current_epoch()?;
        if cur_block_height >= epoch.block_start() + epoch_duration {
            let new_epoch_num =
                ((cur_block_height - epoch.block_start()) / epoch_duration) + epoch.epoch_num();
            let new_epoch = Epoch::new(
                new_epoch_num,
                cur_block_height - (cur_block_height % epoch_duration),
            );
            self.store.save_current_epoch(&new_epoch)?;
            return Ok(new_epoch);
        }
        Ok(epoch)
    }

    pub fn record_participation(
        &mut self,
        _event_id: String,
        _worker: Addr,
        _contract: Addr,
        block_height: u64,
    ) -> Result<(), ContractError> {
        let _cur_epoch = self.update_epoch(block_height)?;
        todo!()
    }

    pub fn process_rewards(
        &mut self,
        _contract: Addr,
        block_height: u64,
    ) -> Result<HashMap<Addr, Uint256>, ContractError> {
        let _cur_epoch = self.update_epoch(block_height)?;
        todo!()
    }

    pub fn update_params(
        &mut self,
        _new_params: RewardsParams,
        block_height: u64,
    ) -> Result<(), ContractError> {
        let _cur_epoch = self.update_epoch(block_height)?;
        todo!()
    }

    pub fn add_rewards(
        &mut self,
        _contract: Addr,
        _amount: Uint256,
        block_height: u64,
    ) -> Result<(), ContractError> {
        let _cur_epoch = self.update_epoch(block_height)?;
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

    /// Tests that the new epoch is computed correctly based on block height and epoch duration
    #[test]
    fn test_update_epoch() {
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
            .update_epoch(current_epoch.block_start() + 1)
            .unwrap();
        assert_eq!(new_epoch, current_epoch);

        // epoch should increase by one
        let block = current_epoch.block_start() + u64::from(config.params.epoch_duration);
        let new_epoch = contract.update_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(Epoch::new(1, block), new_epoch);

        // epoch should increase by one, but start of epoch is in the past
        let block = current_epoch.block_start() + u64::from(config.params.epoch_duration) + 1;
        let new_epoch = contract.update_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(Epoch::new(1, block - 1), new_epoch);

        // epoch should increase by more than one
        let block = current_epoch.block_start() + u64::from(config.params.epoch_duration) * 4;
        let new_epoch = contract.update_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(Epoch::new(4, block), new_epoch);

        // epoch should increase by more than one, but start of epoch is in the past
        let block = current_epoch.block_start() + u64::from(config.params.epoch_duration) * 4 + 10;
        let new_epoch = contract.update_epoch(block).unwrap();
        assert_ne!(new_epoch, current_epoch);
        assert_eq!(Epoch::new(4, block - 10), new_epoch);
    }

    fn create_contract(config: Config, current_epoch: Epoch) -> Contract<state::MockStore> {
        let mut store = state::MockStore::new();
        store
            .expect_load_current_epoch()
            .returning(move || Ok(current_epoch.clone()));
        store.expect_save_current_epoch().returning(|_| Ok(()));
        Contract { store, config }
    }
}

use cosmwasm_std::Storage;
use error_stack::Result;

use crate::{
    error::ContractError,
    msg::RewardsPoolResponse,
    state::{self, Epoch, PoolId},
};

pub fn get_rewards_pool(
    storage: &dyn Storage,
    pool_id: PoolId,
    block_height: u64,
) -> Result<RewardsPoolResponse, ContractError> {
    let pool = state::load_rewards_pool(storage, pool_id.clone())?;
    let stored_params = state::load_params(storage);
    let cur_epoch = Epoch::current(&stored_params, block_height)?;

    let params = match state::load_epoch_tally(storage, pool_id, cur_epoch.epoch_num)? {
        Some(epoch_tally) => epoch_tally.params,
        None => stored_params.params,
    };

    Ok(RewardsPoolResponse {
        balance: pool.balance,
        epoch_duration: params.epoch_duration.into(),
        rewards_per_epoch: params.rewards_per_epoch.into(),
    })
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{testing::mock_dependencies, Addr, Uint128, Uint64};

    use crate::{
        msg::Params,
        state::{EpochTally, RewardsPool, RewardsStore, Store, StoredParams},
    };

    use super::*;

    fn setup(storage: &mut dyn Storage, initial_balance: Uint128) -> (StoredParams, PoolId) {
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("contract"),
        };

        let epoch = Epoch {
            epoch_num: 0,
            block_height_started: 0,
        };

        let params = Params {
            epoch_duration: Uint64::from(100u64).try_into().unwrap(),
            rewards_per_epoch: Uint128::from(1000u128).try_into().unwrap(),
            participation_threshold: (1, 2).try_into().unwrap(),
        };
        let stored_params = StoredParams {
            params: params.clone(),
            last_updated: epoch.clone(),
        };
        let rewards_pool = RewardsPool {
            id: pool_id.clone(),
            balance: initial_balance,
        };

        let mut store = RewardsStore { storage };
        store.save_params(&stored_params).unwrap();
        store.save_rewards_pool(&rewards_pool).unwrap();

        (stored_params, pool_id)
    }

    // Should get rewards pool details, when no tally is found then details are loaded from the stored params
    #[test]
    fn should_get_rewards_pool_with_no_tally() {
        let mut deps = mock_dependencies();
        let balance = Uint128::from(1000u128);
        let (stored_params, pool_id) = setup(deps.as_mut().storage, balance.clone());

        let block_height = 1000;

        let res = get_rewards_pool(deps.as_mut().storage, pool_id.clone(), block_height).unwrap();
        assert_eq!(
            res,
            RewardsPoolResponse {
                balance,
                epoch_duration: stored_params.params.epoch_duration.into(),
                rewards_per_epoch: stored_params.params.rewards_per_epoch.into(),
            }
        );
    }

    // Should get rewards pool details, if there is no tally for current epoch, then details are loaded from the stored params
    // ignoring previous epoch tallies
    #[test]
    fn should_get_rewards_pool_ignoring_old_tallies_details() {
        let mut deps = mock_dependencies();
        let balance = Uint128::from(1000u128);
        let (stored_params, pool_id) = setup(deps.as_mut().storage, balance.clone());

        let old_block_height = 0;

        let tally_params = Params {
            epoch_duration: Uint64::from(200u64).try_into().unwrap(),
            rewards_per_epoch: Uint128::from(2000u128).try_into().unwrap(),
            participation_threshold: (2, 3).try_into().unwrap(),
        };

        let mut store = RewardsStore {
            storage: deps.as_mut().storage,
        };
        store
            .save_epoch_tally(&EpochTally::new(
                pool_id.clone(),
                Epoch::current(&stored_params, old_block_height).unwrap(),
                tally_params.clone(),
            ))
            .unwrap();

        let cur_block_height = 1000;
        let res =
            get_rewards_pool(deps.as_mut().storage, pool_id.clone(), cur_block_height).unwrap();
        assert_eq!(
            res,
            RewardsPoolResponse {
                balance,
                epoch_duration: stored_params.params.epoch_duration.into(),
                rewards_per_epoch: stored_params.params.rewards_per_epoch.into(),
            }
        );
    }

    // Should get rewards pool details, if there is a tally for current epoch, then details are loaded from the tally
    #[test]
    fn should_get_rewards_pool_with_tally_for_current_epoch() {
        let mut deps = mock_dependencies();
        let balance = Uint128::from(1000u128);
        let (stored_params, pool_id) = setup(deps.as_mut().storage, balance.clone());

        let block_height = 1000;

        let tally_params = Params {
            epoch_duration: Uint64::from(200u64).try_into().unwrap(),
            rewards_per_epoch: Uint128::from(2000u128).try_into().unwrap(),
            participation_threshold: (2, 3).try_into().unwrap(),
        };

        let mut store = RewardsStore {
            storage: deps.as_mut().storage,
        };
        store
            .save_epoch_tally(&EpochTally::new(
                pool_id.clone(),
                Epoch::current(&stored_params, block_height).unwrap(),
                tally_params.clone(),
            ))
            .unwrap();

        let res = get_rewards_pool(deps.as_mut().storage, pool_id.clone(), block_height).unwrap();
        assert_eq!(
            res,
            RewardsPoolResponse {
                balance,
                epoch_duration: tally_params.epoch_duration.into(),
                rewards_per_epoch: tally_params.rewards_per_epoch.into(),
            }
        );
    }

    #[test]
    fn should_fail_when_pool_not_found() {
        let mut deps = mock_dependencies();
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("contract"),
        };
        let block_height = 1000;

        let res = get_rewards_pool(deps.as_mut().storage, pool_id.clone(), block_height);
        assert_eq!(
            res.unwrap_err().current_context(),
            &ContractError::RewardsPoolNotFound
        );
    }
}

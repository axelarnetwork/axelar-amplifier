use cosmwasm_std::{Storage, Uint64};
use error_stack::Result;

use crate::error::ContractError;
use crate::msg;
use crate::state::{self, Epoch, PoolId};

pub fn rewards_pool(
    storage: &dyn Storage,
    pool_id: PoolId,
    block_height: u64,
) -> Result<msg::RewardsPool, ContractError> {
    let pool = state::load_rewards_pool(storage, pool_id.clone())?;
    let current_params = pool.params;
    let cur_epoch = Epoch::current(&current_params, block_height)?;

    // the params could have been updated since the tally was created. Therefore we use the params from the
    // active tally if it exists, otherwise we use the latest stored params.
    let params = match state::load_epoch_tally(storage, pool_id.clone(), cur_epoch.epoch_num)? {
        Some(epoch_tally) => epoch_tally.params,
        None => current_params.params,
    };

    let last_distribution_epoch =
        state::load_rewards_watermark(storage, pool_id)?.map(Uint64::from);

    Ok(msg::RewardsPool {
        balance: pool.balance,
        epoch_duration: params.epoch_duration.into(),
        rewards_per_epoch: params.rewards_per_epoch.into(),
        current_epoch_num: cur_epoch.epoch_num.into(),
        last_distribution_epoch,
    })
}

pub fn participation(
    storage: &dyn Storage,
    pool_id: PoolId,
    epoch_num: Option<u64>,
    block_height: u64,
) -> Result<Option<msg::Participation>, ContractError> {
    let epoch_num = match epoch_num {
        Some(num) => num,
        None => {
            let current_params = state::load_rewards_pool_params(storage, pool_id.clone())?;
            Epoch::current(&current_params, block_height)?.epoch_num
        }
    };

    let tally = state::load_epoch_tally(storage, pool_id, epoch_num)?;

    match tally {
        None => Ok(None),
        Some(tally) => Ok(Some(msg::Participation {
            event_count: tally.event_count,
            participation: tally.verifier_participation(),
            rewards_by_verifier: tally.rewards_by_verifier(),
            epoch: tally.epoch,
            params: tally.params,
        })),
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{Addr, Uint128, Uint64};
    use msg::Participation;

    use super::*;
    use crate::msg::Params;
    use crate::state::{EpochTally, ParamsSnapshot, RewardsPool};

    fn setup(storage: &mut dyn Storage, initial_balance: Uint128) -> (ParamsSnapshot, PoolId) {
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
        let params_snapshot = ParamsSnapshot {
            params: params.clone(),
            created_at: epoch.clone(),
        };
        let rewards_pool = RewardsPool {
            id: pool_id.clone(),
            balance: initial_balance,
            params: params_snapshot.clone(),
        };

        state::save_rewards_pool(storage, &rewards_pool).unwrap();

        (params_snapshot, pool_id)
    }

    // Should get rewards pool details, when no tally is found then details are loaded from the stored params
    #[test]
    fn should_get_rewards_pool_with_no_tally() {
        let mut deps = mock_dependencies();
        let balance = Uint128::from(1000u128);
        let (current_params, pool_id) = setup(deps.as_mut().storage, balance);

        let block_height = 1000;

        let res = rewards_pool(deps.as_mut().storage, pool_id.clone(), block_height).unwrap();
        assert_eq!(
            res,
            msg::RewardsPool {
                balance,
                epoch_duration: current_params.params.epoch_duration.into(),
                rewards_per_epoch: current_params.params.rewards_per_epoch.into(),
                current_epoch_num: Epoch::current(&current_params, block_height)
                    .unwrap()
                    .epoch_num
                    .into(),
                last_distribution_epoch: None,
            }
        );
    }

    // Should get rewards pool details with watermark
    #[test]
    fn should_get_rewards_pool_with_watermark() {
        let mut deps = mock_dependencies();
        let balance = Uint128::from(1000u128);
        let (current_params, pool_id) = setup(deps.as_mut().storage, balance);

        let block_height = 1000;
        let last_distribution_epoch = 5u64;

        state::save_rewards_watermark(
            deps.as_mut().storage,
            pool_id.clone(),
            last_distribution_epoch,
        )
        .unwrap();

        let res = rewards_pool(deps.as_mut().storage, pool_id.clone(), block_height).unwrap();
        assert_eq!(
            res,
            msg::RewardsPool {
                balance,
                epoch_duration: current_params.params.epoch_duration.into(),
                rewards_per_epoch: current_params.params.rewards_per_epoch.into(),
                current_epoch_num: Epoch::current(&current_params, block_height)
                    .unwrap()
                    .epoch_num
                    .into(),
                last_distribution_epoch: Some(last_distribution_epoch.into()),
            }
        );
    }

    // Should get rewards pool details, if there is no tally for current epoch, then details are loaded from the stored params
    // ignoring previous epoch tallies
    #[test]
    fn should_get_rewards_pool_ignoring_old_tallies_details() {
        let mut deps = mock_dependencies();
        let balance = Uint128::from(1000u128);
        let (current_params, pool_id) = setup(deps.as_mut().storage, balance);

        let old_block_height = 0;

        let tally_params = Params {
            epoch_duration: Uint64::from(200u64).try_into().unwrap(),
            rewards_per_epoch: Uint128::from(2000u128).try_into().unwrap(),
            participation_threshold: (2, 3).try_into().unwrap(),
        };

        state::save_epoch_tally(
            deps.as_mut().storage,
            &EpochTally::new(
                pool_id.clone(),
                Epoch::current(&current_params, old_block_height).unwrap(),
                tally_params.clone(),
            ),
        )
        .unwrap();

        let cur_block_height = 1000;
        let res = rewards_pool(deps.as_mut().storage, pool_id.clone(), cur_block_height).unwrap();
        assert_eq!(
            res,
            msg::RewardsPool {
                balance,
                epoch_duration: current_params.params.epoch_duration.into(),
                rewards_per_epoch: current_params.params.rewards_per_epoch.into(),
                current_epoch_num: Epoch::current(&current_params, cur_block_height)
                    .unwrap()
                    .epoch_num
                    .into(),
                last_distribution_epoch: None,
            }
        );
    }

    // Should get rewards pool details, if there is a tally for current epoch, then details are loaded from the tally
    #[test]
    fn should_get_rewards_pool_with_tally_for_current_epoch() {
        let mut deps = mock_dependencies();
        let balance = Uint128::from(1000u128);
        let (current_params, pool_id) = setup(deps.as_mut().storage, balance);

        let block_height = 1000;

        let tally_params = Params {
            epoch_duration: Uint64::from(200u64).try_into().unwrap(),
            rewards_per_epoch: Uint128::from(2000u128).try_into().unwrap(),
            participation_threshold: (2, 3).try_into().unwrap(),
        };

        state::save_epoch_tally(
            deps.as_mut().storage,
            &EpochTally::new(
                pool_id.clone(),
                Epoch::current(&current_params, block_height).unwrap(),
                tally_params.clone(),
            ),
        )
        .unwrap();

        let res = rewards_pool(deps.as_mut().storage, pool_id.clone(), block_height).unwrap();
        assert_eq!(
            res,
            msg::RewardsPool {
                balance,
                epoch_duration: tally_params.epoch_duration.into(),
                rewards_per_epoch: tally_params.rewards_per_epoch.into(),
                current_epoch_num: Epoch::current(&current_params, block_height)
                    .unwrap()
                    .epoch_num
                    .into(),
                last_distribution_epoch: None,
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

        let res = rewards_pool(deps.as_mut().storage, pool_id.clone(), block_height);
        assert_eq!(
            res.unwrap_err().current_context(),
            &ContractError::RewardsPoolNotFound
        );
    }

    #[test]
    fn should_get_participation() {
        let mut deps = mock_dependencies();
        let balance = Uint128::from(1000u128);
        let (current_params, pool_id) = setup(deps.as_mut().storage, balance);

        let block_height = 1000;
        let epoch = Epoch::current(&current_params, block_height).unwrap();

        let mut tally = EpochTally::new(
            pool_id.clone(),
            epoch.clone(),
            current_params.params.clone(),
        );
        tally = tally.record_participation(Addr::unchecked("verifier_1"));
        tally = tally.record_participation(Addr::unchecked("verifier_2"));
        tally.event_count = tally.event_count.saturating_add(1);
        state::save_epoch_tally(deps.as_mut().storage, &tally).unwrap();

        let expected = Participation {
            event_count: tally.event_count,
            participation: tally.verifier_participation(),
            rewards_by_verifier: tally.rewards_by_verifier(),
            epoch: Epoch::current(&current_params.clone(), block_height).unwrap(),
            params: current_params.params.clone(),
        };

        // get participation for current epoch
        let res =
            participation(deps.as_mut().storage, pool_id.clone(), None, block_height).unwrap();
        assert_eq!(res.unwrap(), expected);

        // get participation for past epoch
        let res = participation(
            deps.as_mut().storage,
            pool_id.clone(),
            Some(epoch.epoch_num),
            block_height + u64::from(current_params.params.epoch_duration),
        )
        .unwrap();
        assert_eq!(res.unwrap(), expected);
    }

    #[test]
    fn participation_should_return_none_when_no_participation() {
        let mut deps = mock_dependencies();
        let balance = Uint128::from(1000u128);
        let (_, pool_id) = setup(deps.as_mut().storage, balance);

        let block_height = 1000;

        let res =
            participation(deps.as_mut().storage, pool_id.clone(), None, block_height).unwrap();
        assert!(res.is_none());
    }
}

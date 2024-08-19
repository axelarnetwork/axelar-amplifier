use std::collections::HashMap;

use axelar_wasm_std::{nonempty, FnExt};
use cosmwasm_std::{Addr, OverflowError, OverflowOperation, Storage, Uint128};
use error_stack::{ensure, Report, Result};

use crate::error::ContractError;
use crate::msg::Params;
use crate::state::{
    self, Epoch, EpochTally, Event, ParamsSnapshot, PoolId, RewardsDistribution, RewardsPool,
    StorageState,
};

const DEFAULT_EPOCHS_TO_PROCESS: u64 = 10;
const EPOCH_PAYOUT_DELAY: u64 = 2;

pub fn record_participation(
    storage: &mut dyn Storage,
    event_id: nonempty::String,
    verifier: Addr,
    pool_id: PoolId,
    block_height: u64,
) -> Result<(), ContractError> {
    let current_params = state::load_rewards_pool_params(storage, pool_id.clone())?;
    let cur_epoch = Epoch::current(&current_params, block_height)?;

    let event = load_or_store_event(storage, event_id, pool_id.clone(), cur_epoch.epoch_num)?;

    state::load_epoch_tally(storage, pool_id.clone(), event.epoch_num)?
        .unwrap_or(EpochTally::new(pool_id, cur_epoch, current_params.params))
        .record_participation(verifier)
        .then(|mut tally| {
            if matches!(event, StorageState::New(_)) {
                tally.event_count = tally.event_count.saturating_add(1)
            }
            state::save_epoch_tally(storage, &tally)
        })
}

fn load_or_store_event(
    storage: &mut dyn Storage,
    event_id: nonempty::String,
    pool_id: PoolId,
    cur_epoch_num: u64,
) -> Result<StorageState<Event>, ContractError> {
    let event = state::load_event(storage, event_id.to_string(), pool_id.clone())?;

    match event {
        None => {
            let event = Event::new(event_id, pool_id, cur_epoch_num);
            state::save_event(storage, &event)?;
            Ok(StorageState::New(event))
        }
        Some(event) => Ok(StorageState::Existing(event)),
    }
}

pub fn distribute_rewards(
    storage: &mut dyn Storage,
    pool_id: PoolId,
    cur_block_height: u64,
    epoch_process_limit: Option<u64>,
) -> Result<RewardsDistribution, ContractError> {
    let epoch_process_limit = epoch_process_limit.unwrap_or(DEFAULT_EPOCHS_TO_PROCESS);
    let cur_epoch = state::current_epoch(storage, &pool_id, cur_block_height)?;

    let from = state::load_rewards_watermark(storage, pool_id.clone())?
        .map_or(0, |last_processed| last_processed.saturating_add(1));

    let to = std::cmp::min(
        from.saturating_add(epoch_process_limit).saturating_sub(1), // for process limit =1 "from" and "to" must be equal
        cur_epoch.epoch_num.saturating_sub(EPOCH_PAYOUT_DELAY),
    );

    if to < from || cur_epoch.epoch_num < EPOCH_PAYOUT_DELAY {
        return Err(ContractError::NoRewardsToDistribute.into());
    }

    let rewards = process_rewards_for_epochs(storage, pool_id.clone(), from, to)?;
    state::save_rewards_watermark(storage, pool_id, to)?;
    Ok(RewardsDistribution {
        rewards,
        epochs_processed: (from..=to).collect(),
        current_epoch: cur_epoch.clone(),
        can_distribute_more: to < cur_epoch.epoch_num.saturating_sub(EPOCH_PAYOUT_DELAY),
    })
}

fn process_rewards_for_epochs(
    storage: &mut dyn Storage,
    pool_id: PoolId,
    from: u64,
    to: u64,
) -> Result<HashMap<Addr, Uint128>, ContractError> {
    let rewards = cumulate_rewards(storage, &pool_id, from, to)?;
    state::load_rewards_pool(storage, pool_id.clone())?
        .sub_reward(rewards.values().sum())?
        .then(|pool| state::save_rewards_pool(storage, &pool))?;

    Ok(rewards)
}

fn cumulate_rewards(
    storage: &mut dyn Storage,
    pool_id: &PoolId,
    from: u64,
    to: u64,
) -> Result<HashMap<Addr, Uint128>, ContractError> {
    iterate_epoch_tallies(storage, pool_id, from, to)
        .map(|tally| tally.rewards_by_verifier())
        .try_fold(HashMap::new(), merge_rewards)
}

fn iterate_epoch_tallies<'a>(
    storage: &'a mut dyn Storage,
    pool_id: &'a PoolId,
    from: u64,
    to: u64,
) -> impl Iterator<Item = EpochTally> + 'a {
    (from..=to).filter_map(|epoch_num| {
        state::load_epoch_tally(storage, pool_id.clone(), epoch_num).unwrap_or_default()
    })
}

pub fn create_pool(
    storage: &mut dyn Storage,
    params: Params,
    block_height: u64,
    pool_id: &PoolId,
) -> Result<(), ContractError> {
    ensure!(
        !state::pool_exists(storage, pool_id)?,
        ContractError::RewardsPoolAlreadyExists
    );

    let cur_epoch = Epoch {
        epoch_num: 0,
        block_height_started: block_height,
    };

    let params_snapshot = ParamsSnapshot {
        params,
        created_at: cur_epoch,
    };

    let pool = RewardsPool {
        id: pool_id.clone(),
        balance: Uint128::zero(),
        params: params_snapshot,
    };

    state::save_rewards_pool(storage, &pool)
}

pub fn update_pool_params(
    storage: &mut dyn Storage,
    pool_id: &PoolId,
    new_params: Params,
    block_height: u64,
) -> Result<(), ContractError> {
    let cur_epoch = state::current_epoch(storage, pool_id, block_height)?;
    // If the param update reduces the epoch duration such that the current epoch immediately ends,
    // start a new epoch at this block, incrementing the current epoch number by 1.
    // This prevents us from jumping forward an arbitrary number of epochs, and maintains consistency for past events.
    // (i.e. we are in epoch 0, which started at block 0 and epoch duration is 1000. At epoch 500, the params
    // are updated to shorten the epoch duration to 100 blocks. We set the epoch number to 1, to prevent skipping
    // epochs 1-4, and so all events prior to the start of epoch 1 have an epoch number of 0)
    let should_end = cur_epoch
        .block_height_started
        .checked_add(u64::from(new_params.epoch_duration))
        .ok_or_else(|| {
            OverflowError::new(
                OverflowOperation::Add,
                cur_epoch.block_height_started,
                new_params.epoch_duration,
            )
        })
        .map_err(ContractError::from)?
        < block_height;
    let cur_epoch = if should_end {
        Epoch {
            block_height_started: block_height,
            epoch_num: cur_epoch
                .epoch_num
                .checked_add(1)
                .expect("epoch number should be strictly smaller than the current block height"),
        }
    } else {
        cur_epoch
    };
    let new_params_snapshot = ParamsSnapshot {
        params: new_params,
        created_at: cur_epoch,
    };

    state::update_pool_params(storage, pool_id, &new_params_snapshot)?;

    Ok(())
}

pub fn add_rewards(
    storage: &mut dyn Storage,
    pool_id: PoolId,
    amount: nonempty::Uint128,
) -> Result<(), ContractError> {
    let mut pool = state::load_rewards_pool(storage, pool_id)?;
    pool.balance = pool
        .balance
        .checked_add(Uint128::from(amount))
        .map_err(Into::<ContractError>::into)
        .map_err(Report::from)?;

    state::save_rewards_pool(storage, &pool)?;

    Ok(())
}

/// Merges rewards_2 into rewards_1. For each (address, amount) pair in rewards_2,
/// adds the rewards amount to the existing rewards amount in rewards_1. If the
/// address is not yet in rewards_1, initializes the rewards amount to the amount in
/// rewards_2
/// Performs a number of inserts equal to the length of rewards_2
fn merge_rewards(
    rewards_1: HashMap<Addr, Uint128>,
    rewards_2: HashMap<Addr, Uint128>,
) -> Result<HashMap<Addr, Uint128>, ContractError> {
    rewards_2
        .into_iter()
        .try_fold(rewards_1, |mut rewards, (addr, amt)| {
            let r = rewards
                .entry(addr.clone())
                .or_default()
                .checked_add(amt)
                .map_err(Into::<ContractError>::into)
                .map_err(Report::from)?;

            rewards.insert(addr, r);

            Ok(rewards)
        })
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use axelar_wasm_std::nonempty;
    use cosmwasm_std::testing::{mock_dependencies, MockApi, MockQuerier, MockStorage};
    use cosmwasm_std::{Addr, OwnedDeps, Uint128, Uint64};
    use router_api::ChainName;

    use super::*;
    use crate::error::ContractError;
    use crate::msg::Params;
    use crate::state::{self, Config, Epoch, ParamsSnapshot, PoolId, CONFIG};

    /// Tests that the current epoch is computed correctly when the expected epoch is the same as the stored epoch
    #[test]
    fn current_epoch_same_epoch_is_idempotent() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };
        let mock_deps = setup(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            pool_id.clone(),
        );
        let current_params = state::load_rewards_pool(mock_deps.as_ref().storage, pool_id)
            .unwrap()
            .params;

        let new_epoch = Epoch::current(&current_params, block_height_started).unwrap();
        assert_eq!(new_epoch.epoch_num, cur_epoch_num);
        assert_eq!(new_epoch.block_height_started, block_height_started);

        let new_epoch = Epoch::current(&current_params, block_height_started + 1).unwrap();
        assert_eq!(new_epoch.epoch_num, cur_epoch_num);
        assert_eq!(new_epoch.block_height_started, block_height_started);

        let new_epoch =
            Epoch::current(&current_params, block_height_started + epoch_duration - 1).unwrap();
        assert_eq!(new_epoch.epoch_num, cur_epoch_num);
        assert_eq!(new_epoch.block_height_started, block_height_started);
    }

    /// When current epoch is called with a block number that is before the current epoch's start date,
    /// it should return an error
    #[test]
    fn current_epoch_call_with_block_in_the_past() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };
        let mock_deps = setup(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            pool_id.clone(),
        );
        let current_params = state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone())
            .unwrap()
            .params;

        assert!(Epoch::current(&current_params, block_height_started - 1).is_err());
        assert!(Epoch::current(&current_params, block_height_started - epoch_duration).is_err());
    }

    /// Tests that the current epoch is computed correctly when the expected epoch is different from the stored epoch
    #[test]
    fn current_epoch_different_epoch() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };
        let mock_deps = setup(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            pool_id.clone(),
        );

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
            let new_epoch = Epoch::current(
                &state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone())
                    .unwrap()
                    .params,
                height,
            )
            .unwrap();

            assert_eq!(new_epoch.epoch_num, expected_epoch_num);
            assert_eq!(new_epoch.block_height_started, expected_block_start);
        }
    }

    /// Tests that multiple participation events for the same pool within a given epoch are recorded correctly
    #[test]
    fn record_participation_multiple_events() {
        let cur_epoch_num = 1u64;
        let epoch_block_start = 250u64;
        let epoch_duration = 100u64;

        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };
        let mut mock_deps = setup(
            cur_epoch_num,
            epoch_block_start,
            epoch_duration,
            pool_id.clone(),
        );

        let mut simulated_participation = HashMap::new();
        simulated_participation.insert(Addr::unchecked("verifier_1"), 10);
        simulated_participation.insert(Addr::unchecked("verifier_2"), 5);
        simulated_participation.insert(Addr::unchecked("verifier_3"), 7);

        let event_count = 10;
        let mut cur_height = epoch_block_start;
        for i in 0..event_count {
            for (verifier, part_count) in &simulated_participation {
                // simulates a verifier participating in only part_count events
                if i < *part_count {
                    let event_id = i.to_string().try_into().unwrap();
                    record_participation(
                        mock_deps.as_mut().storage,
                        event_id,
                        verifier.clone(),
                        pool_id.clone(),
                        cur_height,
                    )
                    .unwrap();
                }
            }
            cur_height += 1;
        }

        let tally =
            state::load_epoch_tally(mock_deps.as_ref().storage, pool_id, cur_epoch_num).unwrap();
        assert!(tally.is_some());

        let tally = tally.unwrap();
        assert_eq!(tally.event_count, event_count);
        assert_eq!(tally.participation.len(), simulated_participation.len());
        for (verifier, part_count) in simulated_participation {
            assert_eq!(
                tally.participation.get(&verifier.to_string()),
                Some(&part_count)
            );
        }
    }

    /// Tests that the participation event is recorded correctly when the event spans multiple epochs
    #[test]
    fn record_participation_epoch_boundary() {
        let starting_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;

        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };
        let mut mock_deps = setup(
            starting_epoch_num,
            block_height_started,
            epoch_duration,
            pool_id.clone(),
        );

        let verifiers = vec![
            Addr::unchecked("verifier_1"),
            Addr::unchecked("verifier_2"),
            Addr::unchecked("verifier_3"),
        ];
        // this is the height just before the next epoch starts
        let height_at_epoch_end = block_height_started + epoch_duration - 1;
        // verifiers participate in consecutive blocks
        for (i, verifiers) in verifiers.iter().enumerate() {
            record_participation(
                mock_deps.as_mut().storage,
                "some event".try_into().unwrap(),
                verifiers.clone(),
                pool_id.clone(),
                height_at_epoch_end + i as u64,
            )
            .unwrap();
        }

        let cur_epoch = Epoch::current(
            &state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone())
                .unwrap()
                .params,
            height_at_epoch_end,
        )
        .unwrap();
        assert_ne!(starting_epoch_num + 1, cur_epoch.epoch_num);

        let tally = state::load_epoch_tally(
            mock_deps.as_ref().storage,
            pool_id.clone(),
            starting_epoch_num,
        )
        .unwrap();
        assert!(tally.is_some());

        let tally = tally.unwrap();

        assert_eq!(tally.event_count, 1);
        assert_eq!(tally.participation.len(), verifiers.len());
        for w in verifiers {
            assert_eq!(tally.participation.get(&w.to_string()), Some(&1));
        }

        let tally =
            state::load_epoch_tally(mock_deps.as_ref().storage, pool_id, starting_epoch_num + 1)
                .unwrap();
        assert!(tally.is_none());
    }

    /// Tests that participation events for different pools are recorded correctly
    #[test]
    fn record_participation_multiple_contracts() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;

        let mut simulated_participation = HashMap::new();
        simulated_participation.insert(
            Addr::unchecked("verifier-1"),
            (
                PoolId {
                    chain_name: "mock-chain".parse().unwrap(),
                    contract: Addr::unchecked("contract-1"),
                },
                3,
            ),
        );
        simulated_participation.insert(
            Addr::unchecked("verifier-2"),
            (
                PoolId {
                    chain_name: "mock-chain-2".parse().unwrap(),
                    contract: Addr::unchecked("contract-1"),
                },
                4,
            ),
        );
        simulated_participation.insert(
            Addr::unchecked("verifier-3"),
            (
                PoolId {
                    chain_name: "mock-chain".parse().unwrap(),
                    contract: Addr::unchecked("contract-3"),
                },
                2,
            ),
        );

        let params = Params {
            participation_threshold: (1, 2).try_into().unwrap(),
            epoch_duration: 100u64.try_into().unwrap(),
            rewards_per_epoch: 100u128.try_into().unwrap(),
        };
        let mut mock_deps = setup_multiple_pools_with_params(
            cur_epoch_num,
            block_height_started,
            simulated_participation
                .iter()
                .map(|(_, (pool_id, _))| (pool_id.clone(), params.clone()))
                .collect(),
        );

        for (verifier, (pool_contract, events_participated)) in &simulated_participation {
            for i in 0..*events_participated {
                let event_id = i.to_string().try_into().unwrap();
                record_participation(
                    mock_deps.as_mut().storage,
                    event_id,
                    verifier.clone(),
                    pool_contract.clone(),
                    block_height_started,
                )
                .unwrap();
            }
        }
        for (verifier, (pool_contract, events_participated)) in simulated_participation {
            let tally = state::load_epoch_tally(
                mock_deps.as_ref().storage,
                pool_contract.clone(),
                cur_epoch_num,
            )
            .unwrap();

            assert!(tally.is_some());
            let tally = tally.unwrap();

            assert_eq!(tally.event_count, events_participated);
            assert_eq!(tally.participation.len(), 1);
            assert_eq!(
                tally.participation.get(&verifier.to_string()),
                Some(&events_participated)
            );
        }
    }

    /// Test that rewards parameters are updated correctly. In this test we don't change the epoch duration, so
    /// that computation of the current epoch is unaffected.
    #[test]
    fn successfully_update_params() {
        let initial_epoch_num = 1u64;
        let initial_epoch_start = 250u64;
        let initial_rewards_per_epoch = 100u128;
        let initial_participation_threshold = (1, 2);
        let epoch_duration = 100u64;
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };
        let mut mock_deps = setup_with_params(
            initial_epoch_num,
            initial_epoch_start,
            epoch_duration,
            initial_rewards_per_epoch,
            initial_participation_threshold,
            pool_id.clone(),
        );

        // simulate the below tests running at this block height
        let cur_height = initial_epoch_start + epoch_duration * 10 + 2;

        let new_params = Params {
            rewards_per_epoch: cosmwasm_std::Uint128::from(initial_rewards_per_epoch + 100)
                .try_into()
                .unwrap(),
            participation_threshold: (Uint64::new(2), Uint64::new(3)).try_into().unwrap(),
            epoch_duration: epoch_duration.try_into().unwrap(), // keep this the same to not affect epoch computation
        };

        // the epoch shouldn't change when the params are updated, since we are not changing the epoch duration
        let expected_epoch = Epoch::current(
            &state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone())
                .unwrap()
                .params,
            cur_height,
        )
        .unwrap();

        update_pool_params(
            mock_deps.as_mut().storage,
            &pool_id,
            new_params.clone(),
            cur_height,
        )
        .unwrap();
        let stored = state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone())
            .unwrap()
            .params;
        assert_eq!(stored.params, new_params);

        // current epoch shouldn't have changed
        let cur_epoch = Epoch::current(
            &state::load_rewards_pool(mock_deps.as_ref().storage, pool_id)
                .unwrap()
                .params,
            cur_height,
        )
        .unwrap();
        assert_eq!(expected_epoch.epoch_num, cur_epoch.epoch_num);
        assert_eq!(
            expected_epoch.block_height_started,
            cur_epoch.block_height_started
        );

        // last updated should be the current epoch
        assert_eq!(stored.created_at, cur_epoch);
    }

    /// Test extending the epoch duration. This should not change the current epoch
    #[test]
    fn extend_epoch_duration() {
        let initial_epoch_num = 1u64;
        let initial_epoch_start = 250u64;
        let initial_epoch_duration = 100u64;
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };
        let mut mock_deps = setup(
            initial_epoch_num,
            initial_epoch_start,
            initial_epoch_duration,
            pool_id.clone(),
        );

        // simulate the tests running after 5 epochs have passed
        let epochs_elapsed = 5;
        let cur_height = initial_epoch_start + initial_epoch_duration * epochs_elapsed + 10; // add 10 here just to be a little past the epoch boundary

        // epoch shouldn't change if we are extending the duration
        let initial_params_snapshot =
            state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone())
                .unwrap()
                .params;
        let epoch_prior_to_update = Epoch::current(&initial_params_snapshot, cur_height).unwrap();

        let new_epoch_duration = initial_epoch_duration * 2;
        let new_params = Params {
            epoch_duration: new_epoch_duration.try_into().unwrap(),
            ..initial_params_snapshot.params // keep everything besides epoch duration the same
        };

        update_pool_params(
            mock_deps.as_mut().storage,
            &pool_id.clone(),
            new_params.clone(),
            cur_height,
        )
        .unwrap();

        let updated_params_snapshot = state::load_rewards_pool(mock_deps.as_ref().storage, pool_id)
            .unwrap()
            .params;

        // current epoch shouldn't change
        let epoch = Epoch::current(&updated_params_snapshot, cur_height).unwrap();
        assert_eq!(epoch, epoch_prior_to_update);

        // we increased the epoch duration, so adding the initial epoch duration should leave us in the same epoch
        let epoch = Epoch::current(
            &updated_params_snapshot,
            cur_height + initial_epoch_duration,
        )
        .unwrap();
        assert_eq!(epoch, epoch_prior_to_update);

        // check that we can correctly compute the start of the next epoch
        let next_epoch =
            Epoch::current(&updated_params_snapshot, cur_height + new_epoch_duration).unwrap();
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
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };
        let mut mock_deps = setup(
            initial_epoch_num,
            initial_epoch_start,
            initial_epoch_duration,
            pool_id.clone(),
        );

        // simulate the tests running after 10 epochs have passed
        let epochs_elapsed = 10;
        let cur_height = initial_epoch_start + initial_epoch_duration * epochs_elapsed;

        let new_epoch_duration = initial_epoch_duration / 2;

        let initial_params_snapshot =
            state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone())
                .unwrap()
                .params;
        let epoch_prior_to_update = Epoch::current(&initial_params_snapshot, cur_height).unwrap();
        // we are shortening the epoch, but not so much it causes the epoch number to change. We want to remain in the same epoch
        assert!(cur_height - epoch_prior_to_update.block_height_started < new_epoch_duration);

        let new_params = Params {
            epoch_duration: new_epoch_duration.try_into().unwrap(),
            ..initial_params_snapshot.params
        };
        update_pool_params(
            mock_deps.as_mut().storage,
            &pool_id,
            new_params.clone(),
            cur_height,
        )
        .unwrap();

        let updated_params_snapshot =
            state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone())
                .unwrap()
                .params;

        // current epoch shouldn't have changed
        let epoch = Epoch::current(&updated_params_snapshot, cur_height).unwrap();
        assert_eq!(epoch_prior_to_update, epoch);

        // adding the new epoch duration should increase the epoch number by 1
        let epoch =
            Epoch::current(&updated_params_snapshot, cur_height + new_epoch_duration).unwrap();
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
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };
        let mut mock_deps = setup(
            initial_epoch_num,
            initial_epoch_start,
            initial_epoch_duration,
            pool_id.clone(),
        );

        // simulate running the test after 100 epochs have elapsed
        let epochs_elapsed = 100;
        let new_epoch_duration = 10;

        // simulate progressing far enough into the epoch such that shortening the epoch duration would change the epoch
        let cur_height =
            initial_epoch_start + initial_epoch_duration * epochs_elapsed + new_epoch_duration * 2;

        let initial_params_snapshot =
            state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone())
                .unwrap()
                .params;
        let epoch_prior_to_update = Epoch::current(&initial_params_snapshot, cur_height).unwrap();

        let new_params = Params {
            epoch_duration: 10.try_into().unwrap(),
            ..initial_params_snapshot.params
        };
        update_pool_params(
            mock_deps.as_mut().storage,
            &pool_id.clone(),
            new_params.clone(),
            cur_height,
        )
        .unwrap();

        let updated_params_snapshot =
            state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone())
                .unwrap()
                .params;

        // should be in new epoch now
        let epoch = Epoch::current(&updated_params_snapshot, cur_height).unwrap();
        assert_eq!(epoch.epoch_num, epoch_prior_to_update.epoch_num + 1);
        assert_eq!(epoch.block_height_started, cur_height);

        // moving forward the new epoch duration # of blocks should increment the epoch
        let epoch =
            Epoch::current(&updated_params_snapshot, cur_height + new_epoch_duration).unwrap();
        assert_eq!(epoch.epoch_num, epoch_prior_to_update.epoch_num + 2);
        assert_eq!(epoch.block_height_started, cur_height + new_epoch_duration);
    }

    /// Tests that rewards are added correctly to a single pool
    #[test]
    fn added_rewards_should_be_reflected_in_rewards_pool() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };

        let mut mock_deps = setup(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            pool_id.clone(),
        );

        let pool = state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone()).unwrap();
        assert!(pool.balance.is_zero());

        let initial_amount = Uint128::from(100u128);
        add_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            initial_amount.try_into().unwrap(),
        )
        .unwrap();

        let pool = state::load_rewards_pool(mock_deps.as_ref().storage, pool_id.clone()).unwrap();
        assert_eq!(pool.balance, initial_amount);

        let added_amount = Uint128::from(500u128);
        add_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            added_amount.try_into().unwrap(),
        )
        .unwrap();

        let pool = state::load_rewards_pool(mock_deps.as_ref().storage, pool_id).unwrap();
        assert_eq!(pool.balance, initial_amount + added_amount);
    }

    /// Tests that rewards are added correctly with multiple pools
    #[test]
    fn added_rewards_for_multiple_contracts_should_be_reflected_in_multiple_pools() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("some contract"),
        };

        let mut mock_deps = setup(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            pool_id.clone(),
        );
        // a vector of (contract, rewards amounts) pairs
        let test_data = vec![
            (Addr::unchecked("contract_1"), vec![100, 200, 50]),
            (Addr::unchecked("contract_2"), vec![25, 500, 70]),
            (Addr::unchecked("contract_3"), vec![1000, 500, 2000]),
        ];

        let chain_name: ChainName = "mock-chain".parse().unwrap();

        for (pool_contract, rewards) in &test_data {
            let pool_id = PoolId {
                chain_name: chain_name.clone(),
                contract: pool_contract.clone(),
            };
            let participation_threshold = (1, 2);
            let rewards_per_epoch = 100u128;
            create_pool(
                mock_deps.as_mut().storage,
                Params {
                    epoch_duration: epoch_duration.try_into().unwrap(),
                    rewards_per_epoch: rewards_per_epoch.try_into().unwrap(),
                    participation_threshold: participation_threshold.try_into().unwrap(),
                },
                block_height_started,
                &pool_id,
            )
            .unwrap();

            for amount in rewards {
                add_rewards(
                    mock_deps.as_mut().storage,
                    pool_id.clone(),
                    cosmwasm_std::Uint128::from(*amount).try_into().unwrap(),
                )
                .unwrap();
            }
        }

        for (pool_contract, rewards) in test_data {
            let pool_id = PoolId {
                chain_name: chain_name.clone(),
                contract: pool_contract.clone(),
            };

            let pool = state::load_rewards_pool(mock_deps.as_ref().storage, pool_id).unwrap();
            assert_eq!(
                pool.balance,
                cosmwasm_std::Uint128::from(rewards.iter().sum::<u128>())
            );
        }
    }

    /// Tests that pools can have different reward amounts
    #[test]
    fn multiple_pools_different_rewards_amount() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;

        let mut simulated_participation = HashMap::new();
        simulated_participation.insert(
            Addr::unchecked("verifier-1"),
            (
                PoolId {
                    chain_name: "mock-chain".parse().unwrap(),
                    contract: Addr::unchecked("contract-1"),
                },
                3,
            ),
        );
        simulated_participation.insert(
            Addr::unchecked("verifier-2"),
            (
                PoolId {
                    chain_name: "mock-chain-2".parse().unwrap(),
                    contract: Addr::unchecked("contract-1"),
                },
                4,
            ),
        );
        simulated_participation.insert(
            Addr::unchecked("verifier-3"),
            (
                PoolId {
                    chain_name: "mock-chain".parse().unwrap(),
                    contract: Addr::unchecked("contract-3"),
                },
                2,
            ),
        );
        let base_params = Params {
            participation_threshold: (1, 2).try_into().unwrap(),
            epoch_duration: 100u64.try_into().unwrap(),
            rewards_per_epoch: 100u128.try_into().unwrap(), // this is overwritten below
        };
        let rewards_per_epoch = vec![50u128, 100u128, 200u128];
        let pool_params: Vec<(PoolId, Params)> = simulated_participation
            .values()
            .map(|(pool_id, _)| pool_id.clone())
            .zip(rewards_per_epoch.into_iter().map(|r| Params {
                rewards_per_epoch: r.try_into().unwrap(),
                ..base_params.clone()
            }))
            .collect();

        let mut mock_deps = setup_multiple_pools_with_params(
            cur_epoch_num,
            block_height_started,
            pool_params.clone(),
        );

        for (verifier, (pool_contract, events_participated)) in &simulated_participation {
            for i in 0..*events_participated {
                let event_id = i.to_string().try_into().unwrap();
                record_participation(
                    mock_deps.as_mut().storage,
                    event_id,
                    verifier.clone(),
                    pool_contract.clone(),
                    block_height_started,
                )
                .unwrap();
            }
        }

        for (pool_id, params) in pool_params {
            let rewards_to_add = params.rewards_per_epoch;
            let _ = add_rewards(
                mock_deps.as_mut().storage,
                pool_id.clone(),
                Uint128::from(rewards_to_add).try_into().unwrap(),
            );

            let distribution = distribute_rewards(
                mock_deps.as_mut().storage,
                pool_id,
                block_height_started + epoch_duration * 2,
                None,
            )
            .unwrap();
            assert_eq!(
                distribution.rewards.values().sum::<Uint128>(),
                Uint128::from(params.rewards_per_epoch)
            );
        }
    }

    /// Tests that pools can have different participation thresholds
    #[test]
    fn multiple_pools_different_threshold() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let epoch_duration = 100u64;
        let pools = vec![
            PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("contract-1"),
            },
            PoolId {
                chain_name: "mock-chain-2".parse().unwrap(),
                contract: Addr::unchecked("contract-1"),
            },
        ];

        let verifiers = [Addr::unchecked("verifier-1"), Addr::unchecked("verifier-2")];

        // simulate two verifiers each participating in two pools
        // the first verifier participates in 2 events, and the second in 3 events (out of a total of 3 events)
        let simulated_participation = vec![
            (verifiers[0].clone(), (pools[0].clone(), 2)),
            (verifiers[0].clone(), (pools[1].clone(), 2)),
            (verifiers[1].clone(), (pools[0].clone(), 3)),
            (verifiers[1].clone(), (pools[1].clone(), 3)),
        ];
        let base_params = Params {
            participation_threshold: (1, 2).try_into().unwrap(), // this is overwritten below
            epoch_duration: 100u64.try_into().unwrap(),
            rewards_per_epoch: 100u128.try_into().unwrap(),
        };
        // the first pool has a 2/3 threshold, the second 3/4 threshold
        let participation_thresholds = vec![(2, 3), (3, 4)];
        let pool_params: Vec<(PoolId, Params)> = pools
            .clone()
            .into_iter()
            .zip(participation_thresholds.into_iter().map(|p| Params {
                participation_threshold: p.try_into().unwrap(),
                ..base_params.clone()
            }))
            .collect();

        let mut mock_deps = setup_multiple_pools_with_params(
            cur_epoch_num,
            block_height_started,
            pool_params.clone(),
        );

        for (verifier, (pool_contract, events_participated)) in &simulated_participation {
            for i in 0..*events_participated {
                let event_id = i.to_string().try_into().unwrap();
                record_participation(
                    mock_deps.as_mut().storage,
                    event_id,
                    verifier.clone(),
                    pool_contract.clone(),
                    block_height_started,
                )
                .unwrap();
            }
        }

        for (pool_id, params) in pool_params {
            let rewards_to_add = params.rewards_per_epoch;
            let _ = add_rewards(mock_deps.as_mut().storage, pool_id.clone(), rewards_to_add);

            let distribution = distribute_rewards(
                mock_deps.as_mut().storage,
                pool_id.clone(),
                block_height_started + epoch_duration * 2,
                None,
            )
            .unwrap();

            if pool_id == pools[0] {
                // the first pool has a 2/3 threshold, which both verifiers meet
                assert_eq!(
                    distribution.rewards,
                    HashMap::from_iter(verifiers.iter().map(|v| (
                        v.clone(),
                        Uint128::from(Uint128::from(rewards_to_add).u128() / 2)
                    )))
                );
            } else {
                // the second pool has 3/4 threshold, which only the second verifier meets
                assert_eq!(
                    distribution.rewards,
                    HashMap::from([(verifiers[1].clone(), Uint128::from(rewards_to_add))])
                );
            }
        }
    }

    /// Tests that pools can have different epoch lengths
    #[test]
    fn multiple_pools_different_epoch_length() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let base_epoch_duration = 100u64;
        let pools = vec![
            PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("contract-1"),
            },
            PoolId {
                chain_name: "mock-chain-2".parse().unwrap(),
                contract: Addr::unchecked("contract-1"),
            },
        ];

        let verifier = Addr::unchecked("verifier-1");

        // simulate one verifier participating in two events in each pool
        let simulated_participation = vec![
            (verifier.clone(), (pools[0].clone(), 2)),
            (verifier.clone(), (pools[1].clone(), 2)),
        ];

        let base_params = Params {
            participation_threshold: (1, 2).try_into().unwrap(),
            epoch_duration: 100u64.try_into().unwrap(), // this is overwritten below
            rewards_per_epoch: 100u128.try_into().unwrap(),
        };
        // one pool has twice the epoch duration as the other
        let epoch_durations = vec![base_epoch_duration, base_epoch_duration * 2];
        let pool_params: Vec<(PoolId, Params)> = pools
            .clone()
            .into_iter()
            .zip(epoch_durations.into_iter().map(|e| Params {
                epoch_duration: e.try_into().unwrap(),
                ..base_params.clone()
            }))
            .collect();

        let mut mock_deps = setup_multiple_pools_with_params(
            cur_epoch_num,
            block_height_started,
            pool_params.clone(),
        );

        for (verifier, (pool_contract, events_participated)) in &simulated_participation {
            for i in 0..*events_participated {
                let event_id = i.to_string().try_into().unwrap();
                record_participation(
                    mock_deps.as_mut().storage,
                    event_id,
                    verifier.clone(),
                    pool_contract.clone(),
                    block_height_started,
                )
                .unwrap();
            }
        }

        for (pool_id, params) in pool_params {
            let rewards_to_add = params.rewards_per_epoch;
            add_rewards(mock_deps.as_mut().storage, pool_id.clone(), rewards_to_add).unwrap();

            let distribution = distribute_rewards(
                mock_deps.as_mut().storage,
                pool_id.clone(),
                block_height_started + base_epoch_duration * EPOCH_PAYOUT_DELAY, // this is long enough for the first pool to pay out, but not the second
                None,
            )
            .unwrap();

            if pool_id == pools[0] {
                assert_eq!(distribution.rewards.len(), 1);
            } else {
                assert_eq!(distribution.rewards.len(), 0);
            }
        }
    }

    /// Tests that rewards are distributed correctly based on participation
    #[test]
    fn successfully_distribute_rewards() {
        let cur_epoch_num = 0u64;
        let block_height_started = 0u64;
        let epoch_duration = 1000u64;
        let rewards_per_epoch = 100u128;
        let participation_threshold = (2, 3);
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("pool_contract"),
        };

        let mut mock_deps = setup_with_params(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            rewards_per_epoch,
            participation_threshold,
            pool_id.clone(),
        );
        let verifier1 = Addr::unchecked("verifier1");
        let verifier2 = Addr::unchecked("verifier2");
        let verifier3 = Addr::unchecked("verifier3");
        let verifier4 = Addr::unchecked("verifier4");
        let epoch_count = 4;
        // Simulate 4 epochs worth of events with 4 verifiers
        // Each epoch has 3 possible events to participate in
        // The integer values represent which events a specific verifier participated in during that epoch
        // Events in different epochs are considered distinct; we append the epoch number when generating the event id
        // The below participation corresponds to the following:
        // 2 verifiers rewarded in epoch 0, no verifiers in epoch 1 (no events in that epoch), no verifiers in epoch 2 (but still some events), and then 4 (all) verifiers in epoch 3
        let verifier_participation_per_epoch = HashMap::from([
            (
                verifier1.clone(),
                [vec![1, 2, 3], vec![], vec![1], vec![2, 3]], // represents the verifier participated in events 1,2 and 3 in epoch 0, no events in epoch 1, event 1 in epoch 2, and events 2 and 3 in epoch 3
            ),
            (verifier2.clone(), [vec![], vec![], vec![2], vec![1, 2, 3]]),
            (verifier3.clone(), [vec![1, 2], vec![], vec![3], vec![1, 2]]),
            (verifier4.clone(), [vec![1], vec![], vec![2], vec![2, 3]]),
        ]);
        // The expected rewards per verifier over all 4 epochs. Based on the above participation
        let expected_rewards_per_verifier: HashMap<Addr, u128> = HashMap::from([
            (
                verifier1.clone(),
                rewards_per_epoch / 2 + rewards_per_epoch / 4,
            ),
            (verifier2.clone(), rewards_per_epoch / 4),
            (
                verifier3.clone(),
                rewards_per_epoch / 2 + rewards_per_epoch / 4,
            ),
            (verifier4.clone(), rewards_per_epoch / 4),
        ]);

        for (verifier, events_participated) in verifier_participation_per_epoch.clone() {
            for (epoch, events) in events_participated.iter().enumerate().take(epoch_count) {
                for event in events {
                    let event_id = event.to_string() + &epoch.to_string() + "event";
                    let _ = record_participation(
                        mock_deps.as_mut().storage,
                        event_id.clone().try_into().unwrap(),
                        verifier.clone(),
                        pool_id.clone(),
                        block_height_started + epoch as u64 * epoch_duration,
                    );
                }
            }
        }

        // we add 2 epochs worth of rewards. There were 4 epochs of participation, but only 2 epochs where rewards should be given out
        // This tests we are accounting correctly, and only removing from the pool when we actually give out rewards
        let rewards_added = 2 * rewards_per_epoch;
        let _ = add_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            Uint128::from(rewards_added).try_into().unwrap(),
        );

        let distribution = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id,
            block_height_started + epoch_duration * (epoch_count as u64 + 1),
            None,
        )
        .unwrap();

        let rewards_claimed = distribution.rewards;

        assert_eq!(
            rewards_claimed.len(),
            verifier_participation_per_epoch.len()
        );
        for (verifier, rewards) in expected_rewards_per_verifier {
            assert!(rewards_claimed.contains_key(&verifier));
            assert_eq!(
                rewards_claimed.get(&verifier),
                Some(&Uint128::from(rewards))
            );
        }

        assert_eq!(
            distribution.epochs_processed,
            Vec::from_iter(0u64..epoch_count as u64)
        );
    }

    /// Tests that rewards are distributed correctly for a specified number of epochs, and that pagination works correctly
    #[test]
    fn distribute_rewards_specify_epoch_count() {
        let cur_epoch_num = 0u64;
        let block_height_started = 0u64;
        let epoch_duration = 1000u64;
        let rewards_per_epoch = 100u128;
        let participation_threshold = (1, 2);
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("pool_contract"),
        };

        let mut mock_deps = setup_with_params(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            rewards_per_epoch,
            participation_threshold,
            pool_id.clone(),
        );
        let verifier = Addr::unchecked("verifier");

        for height in block_height_started..block_height_started + epoch_duration * 9 {
            let event_id = height.to_string() + "event";
            let _ = record_participation(
                mock_deps.as_mut().storage,
                event_id.try_into().unwrap(),
                verifier.clone(),
                pool_id.clone(),
                height,
            );
        }

        let rewards_added = 1000u128;
        let _ = add_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            Uint128::from(rewards_added).try_into().unwrap(),
        );

        // this puts us in epoch 9
        let cur_height = block_height_started + epoch_duration * 9;
        let total_epochs_with_rewards = (cur_height / epoch_duration) - 1;

        // distribute 5 epochs worth of rewards
        let epochs_to_process = 5;
        let distribution = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            cur_height,
            Some(epochs_to_process),
        )
        .unwrap();
        let rewards_claimed = distribution.rewards;
        assert_eq!(rewards_claimed.len(), 1);
        assert!(rewards_claimed.contains_key(&verifier));
        assert_eq!(
            rewards_claimed.get(&verifier),
            Some(&(rewards_per_epoch * epochs_to_process as u128).into())
        );
        assert_eq!(
            distribution.epochs_processed,
            Vec::from_iter(0u64..epochs_to_process)
        );
        assert_eq!(
            distribution.current_epoch.epoch_num,
            cur_height / epoch_duration
        );
        assert!(distribution.can_distribute_more);

        // distribute the remaining epochs worth of rewards
        let distribution = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            cur_height,
            None,
        )
        .unwrap();
        let rewards_claimed = distribution.rewards;
        assert_eq!(rewards_claimed.len(), 1);
        assert!(rewards_claimed.contains_key(&verifier));
        assert_eq!(
            rewards_claimed.get(&verifier),
            Some(
                &(rewards_per_epoch * (total_epochs_with_rewards - epochs_to_process) as u128)
                    .into()
            )
        );
        assert_eq!(
            distribution.epochs_processed,
            Vec::from_iter(epochs_to_process..total_epochs_with_rewards)
        );
        assert_eq!(
            distribution.current_epoch.epoch_num,
            cur_height / epoch_duration
        );
        assert!(!distribution.can_distribute_more);
    }

    /// Tests that we do not distribute rewards for a given epoch until two epochs later
    #[test]
    fn distribute_rewards_too_early() {
        let cur_epoch_num = 0u64;
        let block_height_started = 0u64;
        let epoch_duration = 1000u64;
        let rewards_per_epoch = 100u128;
        let participation_threshold = (8, 10);
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("pool_contract"),
        };

        let mut mock_deps = setup_with_params(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            rewards_per_epoch,
            participation_threshold,
            pool_id.clone(),
        );
        let verifier = Addr::unchecked("verifier");
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("pool_contract"),
        };

        let _ = record_participation(
            mock_deps.as_mut().storage,
            "event".try_into().unwrap(),
            verifier.clone(),
            pool_id.clone(),
            block_height_started,
        );

        let rewards_added = 1000u128;
        let _ = add_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            Uint128::from(rewards_added).try_into().unwrap(),
        );

        // too early, still in the same epoch
        let err = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            block_height_started,
            None,
        )
        .unwrap_err();
        assert_eq!(err.current_context(), &ContractError::NoRewardsToDistribute);

        // next epoch, but still too early to claim rewards
        let err = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            block_height_started + epoch_duration,
            None,
        )
        .unwrap_err();
        assert_eq!(err.current_context(), &ContractError::NoRewardsToDistribute);

        // can claim now, two epochs after participation
        let distribution = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            block_height_started + epoch_duration * 2,
            None,
        )
        .unwrap();
        assert_eq!(distribution.rewards.len(), 1);
        assert!(!distribution.can_distribute_more);

        // should error if we try again
        let err = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id,
            block_height_started + epoch_duration * 2,
            None,
        )
        .unwrap_err();
        assert_eq!(err.current_context(), &ContractError::NoRewardsToDistribute);
    }

    /// Tests that an error is returned from distribute_rewards when the rewards pool balance is too low to distribute rewards,
    /// and that rewards can later be added and subsequently claimed
    #[test]
    fn distribute_rewards_low_balance() {
        let cur_epoch_num = 0u64;
        let block_height_started = 0u64;
        let epoch_duration = 1000u64;
        let rewards_per_epoch = 100u128;
        let participation_threshold = (8, 10);
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("pool_contract"),
        };

        let mut mock_deps = setup_with_params(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            rewards_per_epoch,
            participation_threshold,
            pool_id.clone(),
        );
        let verifier = Addr::unchecked("verifier");
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("pool_contract"),
        };

        let _ = record_participation(
            mock_deps.as_mut().storage,
            "event".try_into().unwrap(),
            verifier.clone(),
            pool_id.clone(),
            block_height_started,
        );

        // rewards per epoch is 100, we only add 10
        let rewards_added = 10u128;
        let _ = add_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            Uint128::from(rewards_added).try_into().unwrap(),
        );

        let err = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            block_height_started + epoch_duration * 2,
            None,
        )
        .unwrap_err();
        assert_eq!(
            err.current_context(),
            &ContractError::PoolBalanceInsufficient
        );
        // add some more rewards
        let rewards_added = 90u128;
        let _ = add_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            Uint128::from(rewards_added).try_into().unwrap(),
        );

        let distribution = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id,
            block_height_started + epoch_duration * 2,
            None,
        )
        .unwrap();
        assert_eq!(distribution.rewards.len(), 1);
    }

    /// Tests that an error is returned from distribute_rewards when trying to claim rewards for the same epoch more than once
    #[test]
    fn distribute_rewards_already_distributed() {
        let cur_epoch_num = 0u64;
        let block_height_started = 0u64;
        let epoch_duration = 1000u64;
        let rewards_per_epoch = 100u128;
        let participation_threshold = (8, 10);
        let pool_id = PoolId {
            chain_name: "mock-chain".parse().unwrap(),
            contract: Addr::unchecked("pool_contract"),
        };

        let mut mock_deps = setup_with_params(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            rewards_per_epoch,
            participation_threshold,
            pool_id.clone(),
        );
        let verifier = Addr::unchecked("verifier");

        let _ = record_participation(
            mock_deps.as_mut().storage,
            "event".try_into().unwrap(),
            verifier.clone(),
            pool_id.clone(),
            block_height_started,
        );

        let rewards_added = 1000u128;
        let _ = add_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            Uint128::from(rewards_added).try_into().unwrap(),
        );

        let distribution = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id.clone(),
            block_height_started + epoch_duration * 2,
            None,
        )
        .unwrap();
        assert_eq!(distribution.rewards.len(), 1);
        assert_eq!(distribution.epochs_processed, vec![cur_epoch_num]);

        // try to claim again, shouldn't get an error
        let err = distribute_rewards(
            mock_deps.as_mut().storage,
            pool_id,
            block_height_started + epoch_duration * 2,
            None,
        )
        .unwrap_err();
        assert_eq!(err.current_context(), &ContractError::NoRewardsToDistribute);
    }

    #[test]
    fn cannot_record_participation_before_pool_is_created() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let mut mock_deps =
            setup_multiple_pools_with_params(cur_epoch_num, block_height_started, vec![]);

        assert!(record_participation(
            mock_deps.as_mut().storage,
            "some-event".parse().unwrap(),
            Addr::unchecked("verifier"),
            PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("contract")
            },
            block_height_started
        )
        .is_err());
    }

    #[test]
    fn cannot_add_rewards_before_pool_is_created() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let mut mock_deps =
            setup_multiple_pools_with_params(cur_epoch_num, block_height_started, vec![]);
        assert!(add_rewards(
            mock_deps.as_mut().storage,
            PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("contract")
            },
            100u128.try_into().unwrap(),
        )
        .is_err());
    }

    #[test]
    fn cannot_distribute_rewards_before_pool_is_created() {
        let cur_epoch_num = 1u64;
        let block_height_started = 250u64;
        let mut mock_deps =
            setup_multiple_pools_with_params(cur_epoch_num, block_height_started, vec![]);
        assert!(distribute_rewards(
            mock_deps.as_mut().storage,
            PoolId {
                chain_name: "mock-chain".parse().unwrap(),
                contract: Addr::unchecked("contract")
            },
            block_height_started,
            None
        )
        .is_err());
    }

    type MockDeps = OwnedDeps<MockStorage, MockApi, MockQuerier>;

    fn setup_multiple_pools_with_params(
        cur_epoch_num: u64,
        block_height_started: u64,
        pools: Vec<(PoolId, Params)>,
    ) -> MockDeps {
        let current_epoch = Epoch {
            epoch_num: cur_epoch_num,
            block_height_started,
        };

        let mut deps = mock_dependencies();
        let storage = deps.as_mut().storage;
        for (pool_id, params) in pools {
            let params_snapshot = ParamsSnapshot {
                params,
                created_at: current_epoch.clone(),
            };

            state::save_rewards_pool(
                storage,
                &RewardsPool {
                    id: pool_id,
                    params: params_snapshot,
                    balance: Uint128::zero(),
                },
            )
            .unwrap();
        }

        let config = Config {
            rewards_denom: "AXL".to_string(),
        };

        CONFIG.save(storage, &config).unwrap();

        deps
    }

    fn setup_with_params(
        cur_epoch_num: u64,
        block_height_started: u64,
        epoch_duration: u64,
        rewards_per_epoch: u128,
        participation_threshold: (u64, u64),
        pool_id: PoolId,
    ) -> MockDeps {
        let rewards_per_epoch: nonempty::Uint128 = cosmwasm_std::Uint128::from(rewards_per_epoch)
            .try_into()
            .unwrap();
        let current_epoch = Epoch {
            epoch_num: cur_epoch_num,
            block_height_started,
        };

        let params_snapshot = ParamsSnapshot {
            params: Params {
                participation_threshold: participation_threshold.try_into().unwrap(),
                epoch_duration: epoch_duration.try_into().unwrap(),
                rewards_per_epoch,
            },
            created_at: current_epoch.clone(),
        };

        let mut deps = mock_dependencies();
        let storage = deps.as_mut().storage;
        state::save_rewards_pool(
            storage,
            &RewardsPool {
                id: pool_id,
                params: params_snapshot,
                balance: Uint128::zero(),
            },
        )
        .unwrap();

        let config = Config {
            rewards_denom: "AXL".to_string(),
        };

        CONFIG.save(storage, &config).unwrap();

        deps
    }

    fn setup(
        cur_epoch_num: u64,
        block_height_started: u64,
        epoch_duration: u64,
        pool_id: PoolId,
    ) -> MockDeps {
        let participation_threshold = (1, 2);
        let rewards_per_epoch = 100u128;
        setup_with_params(
            cur_epoch_num,
            block_height_started,
            epoch_duration,
            rewards_per_epoch,
            participation_threshold,
            pool_id,
        )
    }
}

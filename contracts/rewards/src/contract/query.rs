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

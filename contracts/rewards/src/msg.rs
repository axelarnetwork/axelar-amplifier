use axelar_wasm_std::{nonempty, Threshold};
use cosmwasm_schema::cw_serde;

#[cw_serde]
pub struct InstantiateMsg {
    governance_address: String,
    rewards_denom: String,
    params: RewardsParams,
}

#[cw_serde]
pub struct RewardsParams {
    /// How often rewards are calculated, specified in number of blocks. Participation is calculated over this window. So if epoch is 500
    /// blocks, workers are rewarded for their participation within each 500 block window.
    epoch_duration: nonempty::Uint64,

    /// Total length of time over which rewards in a pool are distributed, specified in number of blocks. For example, if pool_duration is
    /// 1 million blocks, and epoch_duration is 500 blocks, and total size of the reward pool is 100k tokens, every 500 blocks,
    /// 100k * 500 / 1 million (= 50) tokens are distributed to participating workers. The tokens to be distributed are split equally amongst the participating workers
    pool_duration: nonempty::Uint64,

    /// Participation threshold workers must meet to receive rewards in a given epoch, specified as a fraction between 0 (exclusive) and 1 (exclusive). Workers
    /// must participate in at least this fraction of all events in a given epoch to receive rewards. So, if participation_threshold is 9/10,
    /// and there are 100 events in a given epoch, workers must have participated in at least 90 events to receive rewards.
    /// Participation is reset at the beginning of each epoch, so participation in previous epochs does not affect rewards for future epochs.
    participation_threshold: Threshold,
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Called each time a new event is started, for which workers are rewarded for participating
    StartRewardEvent { event_id: String },

    /// Log a specific worker as participating in a specific event
    RecordParticipation {
        event_id: String,
        worker_address: String,
    },

    /// Process rewards for the most recent epoch, if not yet processed, and send the required number of tokens to each worker
    DistributeRewards {
        /// Address of contract for which to process rewards. For example, address of a voting verifier instance.
        contract_address: String,
    },

    /// Start a new reward pool for the given address if none exists. Otherwise, add tokens to an existing reward pool.
    /// Any attached funds a denom matching the rewards denom are added to the pool.
    AddRewards {
        /// Address of contract for which to reward participation. For example, address of a voting verifier instance.
        contract_address: String,
    },

    /// Overwrites the currently stored params. Callable only by governance.
    UpdateParams { params: RewardsParams },
}

#[cw_serde]
pub enum QueryMsg {}

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
    /// How often rewards are calculated, specified in number of blocks. Participation is calculated over this window. So if epoch_duration is 500
    /// blocks, workers are rewarded for their participation within each 500 block window.
    pub epoch_duration: nonempty::Uint64,

    /// Total number of tokens distributed as rewards per epoch. Tokens are split equally amongst all participating workers for a given epoch
    pub rewards_rate: nonempty::Uint256,

    /// Participation threshold workers must meet to receive rewards in a given epoch, specified as a fraction between 0 (exclusive) and 1 (exclusive). Workers
    /// must participate in at least this fraction of all events in a given epoch to receive rewards. So, if participation_threshold is 9/10,
    /// and there are 100 events in a given epoch, workers must have participated in at least 90 events to receive rewards.
    /// Participation is reset at the beginning of each epoch, so participation in previous epochs does not affect rewards for future epochs.
    pub participation_threshold: Threshold,
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Log a specific worker as participating in a specific event
    RecordParticipation {
        event_id: String,
        worker_address: String,
    },

    /// Distribute rewards up to epoch T - 2 (i.e. if we are currently in epoch 10, distribute all undistributed rewards for epochs 0-8) and send the required number of tokens to each worker
    DistributeRewards {
        /// Address of contract for which to process rewards. For example, address of a voting verifier instance.
        contract_address: String,
    },

    /// Start a new reward pool for the given contract if none exists. Otherwise, add tokens to an existing reward pool.
    /// Any attached funds with a denom matching the rewards denom are added to the pool.
    AddRewards {
        /// Address of contract for which to reward participation. For example, address of a voting verifier instance.
        contract_address: String,
    },

    /// Overwrites the currently stored params. Callable only by governance.
    UpdateParams { params: RewardsParams },
}

#[cw_serde]
pub enum QueryMsg {}

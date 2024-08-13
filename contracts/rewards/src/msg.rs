use std::collections::HashMap;

use axelar_wasm_std::{nonempty, Threshold};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128, Uint64};
use msgs_derive::EnsurePermissions;
use router_api::ChainName;

use crate::state::{Epoch, PoolId};

#[cw_serde]
pub struct InstantiateMsg {
    pub governance_address: String,
    pub rewards_denom: String,
}

#[cw_serde]
pub struct Params {
    /// How often rewards are calculated, specified in number of blocks. Participation is calculated over this window. So if epoch_duration is 500
    /// blocks, verifiers are rewarded for their participation within each 500 block window.
    pub epoch_duration: nonempty::Uint64,

    /// Total number of tokens distributed as rewards per epoch. Tokens are split equally amongst all participating verifiers for a given epoch
    pub rewards_per_epoch: nonempty::Uint128,

    /// Participation threshold verifiers must meet to receive rewards in a given epoch, specified as a fraction between 0 (exclusive) and 1 (exclusive). Verifiers
    /// must participate in at least this fraction of all events in a given epoch to receive rewards. So, if participation_threshold is 9/10,
    /// and there are 100 events in a given epoch, verifiers must have participated in at least 90 events to receive rewards.
    /// Participation is reset at the beginning of each epoch, so participation in previous epochs does not affect rewards for future epochs.
    pub participation_threshold: Threshold,
}

#[cw_serde]
#[derive(EnsurePermissions)]
pub enum ExecuteMsg {
    /// Log a specific verifier as participating in a specific event. Verifier weights are ignored
    /// This call will error if the pool does not yet exist.
    ///
    /// TODO: For batched voting, treating the entire batch as a single event can be problematic.
    /// A verifier may vote correctly for 9 out of 10 messages in a batch, but the verifier's participation
    /// will not be recorded, because of the one message that the verifier voted incorrectly for. Or the voting
    /// verifier could choose to record the participation, but then the missed message is not recorded in any way.
    /// A possible solution to this is to add a weight to each event, where the voting verifier specifies the number
    /// of messages in a batch as well as the number of messages a particular verifier actually participated in.
    #[permission(Any)]
    RecordParticipation {
        chain_name: ChainName,
        event_id: nonempty::String,
        verifier_address: String,
    },

    /// Distribute rewards up to epoch T - 2 (i.e. if we are currently in epoch 10, distribute all undistributed rewards for epochs 0-8) and send the required number of tokens to each verifier
    /// This call will error if the pool does not yet exist.
    #[permission(Any)]
    DistributeRewards {
        pool_id: PoolId,
        /// Maximum number of historical epochs for which to distribute rewards, starting with the oldest. If not specified, distribute rewards for 10 epochs.
        epoch_count: Option<u64>,
    },

    /// Add tokens to an existing rewards pool.
    /// Any attached funds with a denom matching the rewards denom are added to the pool.
    /// This call will error if the pool does not yet exist.
    #[permission(Any)]
    AddRewards { pool_id: PoolId },

    /// Overwrites the currently stored params for the specified pool. Callable only by governance.
    /// This call will error if the pool does not yet exist.
    #[permission(Governance)]
    UpdatePoolParams { params: Params, pool_id: PoolId },

    /// Creates a rewards pool with the specified pool ID and parameters. Callable only by governance.
    #[permission(Governance)]
    CreatePool { params: Params, pool_id: PoolId },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Gets the rewards pool details for the given `pool_id``
    #[returns(RewardsPool)]
    RewardsPool { pool_id: PoolId },

    /// Gets verifier participation info for a given epoch (or the current epoch if unspecified) and pool. If no participation was recorded, returns None
    #[returns(Option<Participation>)]
    VerifierParticipation {
        pool_id: PoolId,
        epoch_num: Option<u64>,
    },
}

#[cw_serde]
pub struct RewardsPool {
    pub balance: Uint128,
    pub epoch_duration: Uint64,
    pub rewards_per_epoch: Uint128,
    pub current_epoch_num: Uint64,
    pub last_distribution_epoch: Option<Uint64>,
}

#[cw_serde]
pub struct Participation {
    pub event_count: u64,
    pub participation: HashMap<Addr, u64>, // maps a verifier address to participation count
    pub rewards_by_verifier: HashMap<Addr, Uint128>, // maps a verifier address to amount of rewards
    pub epoch: Epoch,
    pub params: Params,
}

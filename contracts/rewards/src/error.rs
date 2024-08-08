use axelar_wasm_std::IntoContractError;
use cosmwasm_std::{OverflowError, StdError};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error(transparent)]
    Std(#[from] StdError),

    #[error("error saving params")]
    SaveParams,

    #[error("error saving epoch tally")]
    SaveEpochTally,

    #[error("error saving event")]
    SaveEvent,

    #[error("error saving rewards pool")]
    SaveRewardsPool,

    #[error("error updating rewards pool")]
    UpdateRewardsPool,

    #[error("error saving rewards watermark")]
    SaveRewardsWatermark,

    #[error("error loading epoch tally")]
    LoadEpochTally,

    #[error("error loading event")]
    LoadEvent,

    #[error("error loading rewards pool")]
    LoadRewardsPool,

    #[error("rewards pool not found")]
    RewardsPoolNotFound,

    #[error("rewards pool already exists")]
    RewardsPoolAlreadyExists,

    #[error("error loading rewards watermark")]
    LoadRewardsWatermark,

    #[error("invalid event id")]
    InvalidEventId,

    #[error("specified block has already passed")]
    BlockHeightInPast,

    #[error(transparent)]
    Overflow(#[from] OverflowError),

    #[error("rewards pool balance insufficient")]
    PoolBalanceInsufficient,

    #[error("no rewards to distribute")]
    NoRewardsToDistribute,

    #[error("caller is not authorized")]
    Unauthorized,

    #[error("wrong denom for rewards")]
    WrongDenom,

    #[error("rewards amount is zero")]
    ZeroRewards,

    #[error("failed to serialize the response")]
    SerializeResponse,
}

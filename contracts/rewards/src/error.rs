use axelar_wasm_std_derive::IntoContractError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, IntoContractError)]
pub enum ContractError {
    #[error("error saving params")]
    SaveParams,

    #[error("error saving epoch tally")]
    SaveEpochTally,

    #[error("error saving event")]
    SaveEvent,

    #[error("error saving rewards pool")]
    SaveRewardsPool,

    #[error("error saving rewards watermark")]
    SaveRewardsWatermark,

    #[error("error loading epoch tally")]
    LoadEpochTally,

    #[error("error loading event")]
    LoadEvent,

    #[error("error loading rewards pool")]
    LoadRewardsPool,

    #[error("error loading rewards watermark")]
    LoadRewardsWatermark,

    #[error("invalid event id")]
    InvalidEventId,

    #[error("specified block has already passed")]
    BlockHeightInPast,

    #[error("rewards pool balance insufficient")]
    PoolBalanceInsufficient,

    #[error("no rewards to distribute")]
    NoRewardsToDistribute,
}

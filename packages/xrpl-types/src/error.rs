use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum XRPLError {
    #[error("failed to encode signature")]
    FailedToEncodeSignature,

    #[error("failed to serialize transaction")]
    FailedToSerialize,

    #[error("invalid address {0}")]
    InvalidAddress(String),

    #[error("invalid amount: {reason}")]
    InvalidAmount { reason: String },

    #[error("invalid currency")]
    InvalidCurrency,

    #[error("invalid decimals {0}")]
    InvalidDecimals(u8),

    #[error("invalid drops {0}")]
    InvalidDrops(u64),

    #[error("invalid message ID {0}")]
    InvalidMessageId(String),

    #[error("incompatible tokens")]
    IncompatibleTokens,

    #[error("invalid transaction hash")]
    InvalidTxId,

    #[error("overflow")]
    Overflow,

    #[error(transparent)]
    Std(#[from] StdError),

    #[error("underflow")]
    Underflow,
}

impl From<XRPLError> for StdError {
    fn from(value: XRPLError) -> Self {
        Self::generic_err(value.to_string())
    }
}

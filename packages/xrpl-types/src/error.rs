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

    #[error("invalid message ID {0}")]
    InvalidMessageId(String),

    #[error("invalid transaction hash")]
    InvalidTxId,

    #[error("overflow")]
    Overflow,

    #[error(transparent)]
    Std(#[from] StdError),
}

impl From<XRPLError> for StdError {
    fn from(value: XRPLError) -> Self {
        Self::generic_err(value.to_string())
    }
}

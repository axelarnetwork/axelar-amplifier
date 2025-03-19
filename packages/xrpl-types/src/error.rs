use cosmwasm_std::{StdError, Uint256};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum XRPLError {
    #[error("addition overflow")]
    AdditionOverflow,

    #[error("canonicalized amount exceeds original amount")]
    CanonicalizedAmountExceedsOriginal,

    #[error("division by zero")]
    DivisionByZero,

    #[error("drops too large")]
    DropsTooLarge,

    #[error("exponent overflow")]
    ExponentOverflow,

    #[error("exponentiation overflow")]
    ExponentiationOverflow,

    #[error("failed to canonicalize matissa {mantissa} with exponent {exponent}")]
    FailedToCanonicalizeMatissa { mantissa: Uint256, exponent: i8 },

    #[error("failed to encode signature")]
    FailedToEncodeSignature,

    #[error("failed to serialize transaction")]
    FailedToSerialize,

    #[error("invalid address {0}")]
    InvalidAddress(String),

    #[error("invalid token amount: {reason}")]
    InvalidTokenAmount { reason: String },

    #[error("invalid currency")]
    InvalidCurrency,

    #[error("invalid decimals {0}")]
    InvalidDecimals(u8),

    #[error("invalid exponent")]
    InvalidExponent,

    #[error("invalid message ID {0}")]
    InvalidMessageId(String),

    #[error("invalid signer weight {0}")]
    InvalidSignerWeight(u16),

    #[error("incompatible tokens")]
    IncompatibleTokens,

    #[error("invalid transaction hash")]
    InvalidTxId,

    #[error("mantissa overflow")]
    MantissaOverflow,

    #[error("multiplication overflow")]
    MultiplicationOverflow,

    #[error("negation overflow")]
    NegationOverflow,

    #[error("overflow")]
    Overflow,

    #[error(transparent)]
    Std(#[from] StdError),

    #[error("subtraction underflow")]
    SubtractionUnderflow,

    #[error("underflow")]
    Underflow,

    #[error("unsupported key type")]
    UnsupportedKeyType,
}

impl From<XRPLError> for StdError {
    fn from(value: XRPLError) -> Self {
        Self::generic_err(value.to_string())
    }
}

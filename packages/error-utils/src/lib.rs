mod error;
pub mod loggable;
#[cfg(feature = "eyre")]
pub mod result_ext;

#[cfg(feature = "contracts")]
pub use error_utils_derive::IntoContractError;

#[cfg(feature = "contracts")]
pub use crate::error::*;

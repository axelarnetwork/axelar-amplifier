pub mod traits;

#[cfg(feature = "evm")]
mod evm;
#[cfg(feature = "evm")]
pub use crate::encoding::evm::{Data, Message};

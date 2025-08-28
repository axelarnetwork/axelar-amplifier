#[cfg(not(any(feature = "evm", feature = "sui", feature = "stellar")))]
compile_error!("Exactly one of the chain-features must be enabled.");

// these are only used if the respective feature is enabled, so we silence the warnings
// we could also feature-gate them, but that makes editing them a big pain because they are mutually
// exclusive, so you cannot enable all of them at once.
// We also use some of them in tests
#[allow(unused)]
mod evm;
#[allow(unused)]
mod stellar;
#[allow(unused)]
mod sui;

#[cfg(feature = "evm")]
pub use evm::*;
#[cfg(feature = "stellar")]
pub use stellar::*;
#[cfg(feature = "sui")]
pub use sui::*;

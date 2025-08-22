// these are only used if the respective feature is enabled, so we silence the warnings
// we could also feature-gate them, but that makes editing them a big pain
#[allow(unused)]
mod abi;
#[allow(unused)]
mod bcs;
#[allow(unused)]
mod stellar_xdr;

#[cfg(not(any(feature = "evm", feature = "sui", feature = "stellar_xdr")))]
compile_error!("Exactly one of the chain-features must be enabled.");

pub mod contract;
mod error;
pub mod state;

pub use chain_codec_api::msg;

#[cfg(test)]
mod test;

mod abi;
mod bcs;
mod stellar_xdr;

#[cfg(not(any(feature = "evm", feature = "sui", feature = "stellar_xdr")))]
compile_error!("Exactly one of the chain-features must be enabled.");

pub mod contract;
mod error;
pub mod state;

pub use chain_codec_api::msg;

#[cfg(test)]
mod test;

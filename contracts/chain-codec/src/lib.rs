#[cfg(not(feature = "sui"))]
mod abi;
#[cfg(feature = "sui")]
mod bcs;
pub mod contract;
mod error;
pub mod state;

pub use chain_codec_api::msg;

#[cfg(test)]
mod test;

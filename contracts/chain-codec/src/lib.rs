pub mod contract;
mod encoding;
mod error;
pub mod state;

pub use chain_codec_api::msg;

#[cfg(test)]
mod test;

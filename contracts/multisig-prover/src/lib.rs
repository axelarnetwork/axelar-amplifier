pub mod contract;
pub mod error;
pub mod events;
pub mod msg;
mod state;

pub use multisig_prover_api::payload::Payload;

#[cfg(test)]
mod test;

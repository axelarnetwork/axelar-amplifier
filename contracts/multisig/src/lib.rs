mod client;
pub use client::Client;
pub mod contract;
pub mod error;

mod events;
pub use events::Event;
mod legacy_events;
pub use legacy_events::LegacyEvent;

pub mod key;
pub mod msg;
pub mod multisig;
mod signing;
mod state;
pub mod types;
pub mod verifier_set;

#[cfg(feature = "secp256k1")]
mod secp256k1;

#[cfg(feature = "ed25519")]
mod ed25519;

#[cfg(any(test, feature = "test"))]
pub mod test;

pub use crate::error::ContractError;

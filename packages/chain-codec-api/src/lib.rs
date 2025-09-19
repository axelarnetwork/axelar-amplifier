mod client;
pub mod error;
pub mod msg;
pub mod state;

pub use client::{Client, ClientError};
// Re-exporting types here to avoid implementors having to import them from multiple places
pub use multisig::{msg::SignerWithSig, verifier_set::VerifierSet};
pub use multisig_prover_api::payload::Payload;

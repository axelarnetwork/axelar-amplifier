mod client;
pub mod msg;
pub mod error;

pub use client::Client;

// Re-exporting types here to avoid implementors having to import them from multiple places
pub use multisig::{msg::SignerWithSig, verifier_set::VerifierSet};
pub use multisig_prover_api::payload::Payload;
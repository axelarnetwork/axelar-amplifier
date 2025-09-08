pub mod aleo_struct;
pub mod multisig_prover;
mod safe_gmp_chain_name;
pub use safe_gmp_chain_name::*;
pub mod utils;

pub mod error;

/// Used for chain names used in Aleo GMP
pub type GmpChainName = [u128; 2];

/// Used for message ids used in Aleo GMP
pub type GmpMessageId = [u128; 8];

pub const GMP_ADDRESS_LENGTH: usize = 6;

/// Used for addresses used in Aleo GMP
pub type GmpAddress = [u128; GMP_ADDRESS_LENGTH];

/// ITS token id used in Aleo ITS
pub type ItsTokenId = [u128; 2];

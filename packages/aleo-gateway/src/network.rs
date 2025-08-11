use std::fmt;

use cosmwasm_schema::cw_serde;
use snarkvm_cosmwasm::prelude::{CanaryV0, MainnetV0, Network, TestnetV0};

/// Represents the Aleo network configuration.
///
/// To reduce the dependencies on Aleo crates we will define our own type here for representing
/// Aleo Network
#[cw_serde]
pub enum NetworkConfig {
    #[serde(rename = "testnet")]
    TestnetV0,
    #[serde(rename = "mainnet")]
    MainnetV0,
    #[serde(rename = "canary")]
    CanaryV0,
}

impl NetworkConfig {
    pub fn id(&self) -> u16 {
        match self {
            NetworkConfig::TestnetV0 => TestnetV0::ID,
            NetworkConfig::MainnetV0 => MainnetV0::ID,
            NetworkConfig::CanaryV0 => CanaryV0::ID,
        }
    }
}

impl fmt::Display for NetworkConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NetworkConfig::TestnetV0 => write!(f, "testnet"),
            NetworkConfig::MainnetV0 => write!(f, "mainnet"),
            NetworkConfig::CanaryV0 => write!(f, "canary"),
        }
    }
}

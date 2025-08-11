use std::str::FromStr as _;

use snarkvm_cosmwasm::prelude::{Address, CanaryV0, MainnetV0, ProgramID, TestnetV0};

use crate::error::AleoError;
use crate::network::NetworkConfig;

pub fn validate_program_name(network: &NetworkConfig, address: &str) -> Result<(), AleoError> {
    match network {
        NetworkConfig::TestnetV0 => {
            ProgramID::<TestnetV0>::from_str(address)?;
        }
        NetworkConfig::MainnetV0 => {
            ProgramID::<MainnetV0>::from_str(address)?;
        }
        NetworkConfig::CanaryV0 => {
            ProgramID::<CanaryV0>::from_str(address)?;
        }
    }

    Ok(())
}

pub fn validate_address(network: &NetworkConfig, address: &str) -> Result<(), AleoError> {
    match network {
        NetworkConfig::TestnetV0 => {
            Address::<TestnetV0>::from_str(address)?;
        }
        NetworkConfig::MainnetV0 => {
            Address::<MainnetV0>::from_str(address)?;
        }
        NetworkConfig::CanaryV0 => {
            Address::<CanaryV0>::from_str(address)?;
        }
    }

    Ok(())
}

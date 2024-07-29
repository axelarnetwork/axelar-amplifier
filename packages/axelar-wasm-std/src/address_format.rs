use alloy_primitives::Address;
use cosmwasm_schema::cw_serde;
use error_stack::{Report, ResultExt};

#[derive(thiserror::Error)]
#[cw_serde]
pub enum Error {
    #[error("invalid address '{0}'")]
    InvalidAddress(String),
}

#[cw_serde]
pub enum AddressFormat {
    Eip55,
}

pub fn validate_address(address: &str, format: &AddressFormat) -> Result<(), Report<Error>> {
    match format {
        AddressFormat::Eip55 => Address::parse_checksummed(address, None)
            .change_context(Error::InvalidAddress(address.to_string()))
            .map(|_| ()),
    }
}

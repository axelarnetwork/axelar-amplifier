use alloy_primitives::Address;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Api};
use error_stack::{Result, ResultExt};

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

pub fn validate_address(address: &str, format: &AddressFormat) -> Result<(), Error> {
    match format {
        AddressFormat::Eip55 => Address::parse_checksummed(address, None)
            .change_context(Error::InvalidAddress(address.to_string()))?,
    };

    Ok(())
}

pub fn validate_cosmwasm_address(api: &dyn Api, addr: &str) -> Result<Addr, Error> {
    api.addr_validate(addr)
        .change_context(Error::InvalidAddress(addr.to_string()))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::MockApi;

    use super::*;
    use crate::err_contains;

    #[test]
    fn test_validate_address() {
        let addr = "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5";

        assert!(validate_address(addr, &AddressFormat::Eip55).is_ok());

        let without_prefix = addr.strip_prefix("0x").unwrap();
        assert!(validate_address(without_prefix, &AddressFormat::Eip55).is_err());

        let lower_case = addr.to_lowercase();
        assert!(validate_address(&lower_case, &AddressFormat::Eip55).is_err());

        let upper_case = addr.to_uppercase();
        assert!(validate_address(&upper_case, &AddressFormat::Eip55).is_err());
    }

    #[test]
    fn test_validate_cosmwasm_address() {
        let api = MockApi::default();
        let addr = "axelar1x46rqay4d3cssq8gxxvqz8xt6nwlz4td20k38v";
        assert!(validate_cosmwasm_address(&api, &addr).is_ok());

        let upper_case = addr.to_uppercase();
        assert!(err_contains!(
            validate_cosmwasm_address(&api, &upper_case).unwrap_err(),
            Error,
            Error::InvalidAddress(..)
        ));
    }
}

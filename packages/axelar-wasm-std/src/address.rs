use std::str::FromStr;

use alloy_primitives::Address;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Api};
use error_stack::{bail, Result, ResultExt};
use stellar_xdr::curr::ScAddress;
use sui_types::SuiAddress;

#[derive(thiserror::Error)]
#[cw_serde]
pub enum Error {
    #[error("invalid address '{0}'")]
    InvalidAddress(String),
}

#[cw_serde]
pub enum AddressFormat {
    Eip55,
    Sui,
    Stellar,
}

pub fn validate_address(address: &str, format: &AddressFormat) -> Result<(), Error> {
    match format {
        AddressFormat::Eip55 => {
            Address::parse_checksummed(address, None)
                .change_context(Error::InvalidAddress(address.to_string()))?;
        }
        AddressFormat::Sui => {
            SuiAddress::from_str(address)
                .change_context(Error::InvalidAddress(address.to_string()))?;
        }
        AddressFormat::Stellar => {
            if address != address.to_uppercase() {
                bail!(Error::InvalidAddress(address.to_string()))
            }
            ScAddress::from_str(address)
                .change_context(Error::InvalidAddress(address.to_string()))?;
        }
    }

    Ok(())
}

pub fn validate_cosmwasm_address(api: &dyn Api, addr: &str) -> Result<Addr, Error> {
    api.addr_validate(addr)
        .change_context(Error::InvalidAddress(addr.to_string()))
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use cosmwasm_std::testing::MockApi;

    use crate::{address, assert_err_contains};

    #[test]
    fn validate_eip55_address() {
        let addr = "0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5";

        assert_ok!(address::validate_address(
            addr,
            &address::AddressFormat::Eip55
        ));

        let without_prefix = addr.strip_prefix("0x").unwrap();
        assert_err_contains!(
            address::validate_address(without_prefix, &address::AddressFormat::Eip55),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        let lower_case = addr.to_lowercase();
        assert_err_contains!(
            address::validate_address(&lower_case, &address::AddressFormat::Eip55),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        let upper_case = addr.to_uppercase();
        assert_err_contains!(
            address::validate_address(&upper_case, &address::AddressFormat::Eip55),
            address::Error,
            address::Error::InvalidAddress(..)
        );
    }

    #[test]
    fn validate_sui_address() {
        let addr = "0x8cc8d18733a4bf98de8f861d356e2191918733e3afff29f327a01b5ba2997a4d";

        assert_ok!(address::validate_address(
            addr,
            &address::AddressFormat::Sui
        ));

        let without_prefix = addr.strip_prefix("0x").unwrap();
        assert_err_contains!(
            address::validate_address(without_prefix, &address::AddressFormat::Sui),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        let upper_case = addr.to_uppercase();
        assert_err_contains!(
            address::validate_address(&upper_case, &address::AddressFormat::Sui),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        let mixed_case = addr
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().next().unwrap()
                } else {
                    c
                }
                .to_string()
            })
            .collect::<String>();
        assert_err_contains!(
            address::validate_address(&mixed_case, &address::AddressFormat::Sui),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        let invalid_length = format!("{}5f", addr);
        assert_err_contains!(
            address::validate_address(&invalid_length, &address::AddressFormat::Sui),
            address::Error,
            address::Error::InvalidAddress(..)
        );
    }

    #[test]
    fn validate_cosmwasm_address() {
        let api = MockApi::default();
        let addr = "axelar1x46rqay4d3cssq8gxxvqz8xt6nwlz4td20k38v";
        assert_ok!(address::validate_cosmwasm_address(&api, addr));

        let upper_case = addr.to_uppercase();
        assert_err_contains!(
            address::validate_cosmwasm_address(&api, &upper_case),
            address::Error,
            address::Error::InvalidAddress(..)
        );
    }

    #[test]
    fn validate_stellar_address() {
        // account id
        let addr = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";
        assert_ok!(address::validate_address(
            addr,
            &address::AddressFormat::Stellar
        ));

        let lower_case = addr.to_lowercase();
        assert_err_contains!(
            address::validate_address(&lower_case, &address::AddressFormat::Stellar),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // contract
        let addr = "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA";
        assert_ok!(address::validate_address(
            addr,
            &address::AddressFormat::Stellar
        ));

        let lower_case = addr.to_lowercase();
        assert_err_contains!(
            address::validate_address(&lower_case, &address::AddressFormat::Stellar),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // invalid
        let invalid = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";
        assert_err_contains!(
            address::validate_address(invalid, &address::AddressFormat::Stellar),
            address::Error,
            address::Error::InvalidAddress(..)
        );
    }
}

use std::str::FromStr;

use alloy_primitives::Address;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{ensure, Addr, Api};
use error_stack::{bail, Result, ResultExt};
use starknet_checked_felt::CheckedFelt;
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
    Solana,
    Starknet,
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
            if address.starts_with('M') {
                bail!(Error::InvalidAddress(address.to_string()))
            }
            ScAddress::from_str(address)
                .change_context(Error::InvalidAddress(address.to_string()))?;
        }
        AddressFormat::Solana => {
            const SOLANA_PUBKEY_LEN: usize = 32;
            const MAX_ADDRESS_LEN: usize = 44;
            const MIN_ADDRESS_LEN: usize = 32;

            ensure!(
                (MIN_ADDRESS_LEN..=MAX_ADDRESS_LEN).contains(&address.len()),
                Error::InvalidAddress(address.to_string())
            );

            let pubkey = bs58::decode(address)
                .into_vec()
                .change_context(Error::InvalidAddress(address.to_string()))?;

            ensure!(
                pubkey.len() == SOLANA_PUBKEY_LEN,
                Error::InvalidAddress(address.to_string())
            );
        }
        AddressFormat::Starknet => {
            CheckedFelt::from_str(address)
                .change_context(Error::InvalidAddress(address.to_string()))?;
        }
    }

    Ok(())
}

pub fn validate_cosmwasm_address(api: &dyn Api, addr: &str) -> Result<Addr, Error> {
    api.addr_validate(addr)
        .change_context(Error::InvalidAddress(addr.to_string()))
}

/// Type alias for contract addresses. Used to avoid suffixing variables with _contract
pub type ContractAddr = Addr;

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
        let api = MockApi::default().with_prefix("axelar");
        let addr = "axelar1xsyqml4kz53jk0udu9lkmr7tmg3gx08r7mjn68";
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

        // muxed address - supported in protocol V23 but we consider it as invalid
        // unless there is a clear requirement to support these address types
        let muxed_addr = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";
        assert_err_contains!(
            address::validate_address(muxed_addr, &address::AddressFormat::Stellar),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        let lower_case = muxed_addr.to_lowercase();
        assert_err_contains!(
            address::validate_address(&lower_case, &address::AddressFormat::Stellar),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // invalid - use clearly malformed address with invalid characters
        let invalid = "INVALID_STELLAR_ADDRESS_WITH_BAD_CHARS_123!@#";
        assert_err_contains!(
            address::validate_address(invalid, &address::AddressFormat::Stellar),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        let lower_case = invalid.to_lowercase();
        assert_err_contains!(
            address::validate_address(&lower_case, &address::AddressFormat::Stellar),
            address::Error,
            address::Error::InvalidAddress(..)
        );
    }

    #[test]
    fn validate_solana_address() {
        use crate::{address, assert_err_contains};
        // Valid Solana address
        let addr = "4f3J7t1HgX1t36k6rph2pYJrWxk9uT1RrB2K3nVHDh8D";
        assert_ok!(address::validate_address(
            addr,
            &address::AddressFormat::Solana
        ));

        // Valid Solana address (all 32 bytes equal to 0)
        let addr = "11111111111111111111111111111111";
        assert_ok!(address::validate_address(
            addr,
            &address::AddressFormat::Solana
        ));

        // Invalid address: contains invalid character '0' (zero)
        let invalid_char_addr = "4f3J7t1HgX1t36k6rph2pYJrWxk9uT1RrB2K3nVHDh8D0";
        assert_err_contains!(
            address::validate_address(invalid_char_addr, &address::AddressFormat::Solana),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // Invalid address: contains invalid character 'O'
        let invalid_char_addr2 = "4f3J7t1HgX1t36k6rph2pYJrWxk9uT1RrB2K3nVHDh8DO";
        assert_err_contains!(
            address::validate_address(invalid_char_addr2, &address::AddressFormat::Solana),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // Invalid address: incorrect length (too short)
        let short_addr = "4f3J7t1HgX1t36k6rph2pYJrWxk9uT1RrB2K3nVHDh";
        assert_err_contains!(
            address::validate_address(short_addr, &address::AddressFormat::Solana),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // Invalid address: incorrect length (too long)
        let long_addr = format!("{}A", addr);
        assert_err_contains!(
            address::validate_address(&long_addr, &address::AddressFormat::Solana),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // Invalid address: contains invalid character 'I'
        let invalid_char_addr3 = "4f3J7t1HgX1t36k6rph2pYJrWxk9uT1RrB2K3nVHDh8DI";
        assert_err_contains!(
            address::validate_address(invalid_char_addr3, &address::AddressFormat::Solana),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // Invalid address: contains invalid character 'l'
        let invalid_char_addr4 = "4f3J7t1HgX1t36k6rph2pYJrWxk9uT1RrB2K3nVHDh8Dl";
        assert_err_contains!(
            address::validate_address(invalid_char_addr4, &address::AddressFormat::Solana),
            address::Error,
            address::Error::InvalidAddress(..)
        );
    }

    #[test]
    fn validate_starknet_address() {
        // 0 prefixed field element
        // 64 chars
        let addr = "0x0282b4492e08d8b6bbec8dfe7412e42e897eef9c080c5b97be1537433e583bdc";
        assert_ok!(address::validate_address(
            addr,
            &address::AddressFormat::Starknet
        ));

        // 0x prefix removed from string, but padded with 0
        // 64 chars
        let zero_x_removed = "0282b4492e08d8b6bbec8dfe7412e42e897eef9c080c5b97be1537433e583bdc";
        assert_err_contains!(
            address::validate_address(zero_x_removed, &address::AddressFormat::Starknet),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // 0x0 prefix removed from string.
        // Commonly a `0` is prefixed to the field element, in order to make it a valid hex.
        // Originally the felt is 63 chars, which is an invalid hex by itself
        // 63 chars
        let zero_x_zero_removed = "282b4492e08d8b6bbec8dfe7412e42e897eef9c080c5b97be1537433e583bdc";
        assert_err_contains!(
            address::validate_address(zero_x_zero_removed, &address::AddressFormat::Starknet),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // 0 prefix removed from string, but 0x is left in.
        // This is an invalid 63char hex by itself, but a valid field element.
        // 63 chars.
        let zero_removed = "0x282b4492e08d8b6bbec8dfe7412e42e897eef9c080c5b97be1537433e583bdc";
        assert_err_contains!(
            address::validate_address(zero_removed, &address::AddressFormat::Starknet),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // invalid hex (starts with `q`)
        let invalid_hex = "0xq282b4492e08d8b6bbec8dfe7412e42e897eef9c080c5b97be1537433e583bdc";
        assert_err_contains!(
            address::validate_address(invalid_hex, &address::AddressFormat::Starknet),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // more than 64 chars is invalid
        let more_than_64 = "0x282b4492e08d8b6bbec8dfe7412e42e897eef9c080c5b97be1537433e583bdc123";
        assert_err_contains!(
            address::validate_address(more_than_64, &address::AddressFormat::Starknet),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // less than 63 chars is invalid
        let less_than_63 = "0x123";
        assert_err_contains!(
            address::validate_address(less_than_63, &address::AddressFormat::Starknet),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        let overflown_felt_with_one =
            "0x080000006b9f1bed878fcc665f2ca1a6afd545a6b864d8400000000000000001";
        assert_err_contains!(
            address::validate_address(overflown_felt_with_one, &address::AddressFormat::Starknet),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // overflowed field element (added a 64th char, other than 0)
        let overflown_felt = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert_err_contains!(
            address::validate_address(overflown_felt, &address::AddressFormat::Starknet),
            address::Error,
            address::Error::InvalidAddress(..)
        );

        // uppercase string field element
        let upper_case_invalid = addr.to_uppercase();
        assert_err_contains!(
            address::validate_address(
                upper_case_invalid.as_str(),
                &address::AddressFormat::Starknet
            ),
            address::Error,
            address::Error::InvalidAddress(..)
        );
    }
}

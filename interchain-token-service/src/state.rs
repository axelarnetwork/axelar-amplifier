use axelar_wasm_std::IntoContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, Storage};
use cw_storage_plus::{Item, Map};
use router_api::{Address, ChainName, ChainNameRaw};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error("ITS contract got into an invalid state, its config is missing")]
    MissingConfig,
    #[error("trusted address for chain {0} not found")]
    TrustedAddressNotFound(ChainName),
}

#[cw_serde]
pub struct Config {
    pub chain_name: ChainNameRaw,
    pub gateway: Addr,
}

const CONFIG: Item<Config> = Item::new("config");
const TRUSTED_ITS_ADDRESSES: Map<&ChainName, Address> = Map::new("trusted_its_addresses");

pub(crate) fn load_config(storage: &dyn Storage) -> Result<Config, Error> {
    CONFIG
        .may_load(storage)
        .map_err(Error::from)?
        .ok_or(Error::MissingConfig)
}

pub(crate) fn save_config(storage: &mut dyn Storage, config: &Config) -> Result<(), Error> {
    CONFIG.save(storage, config).map_err(Error::from)
}

pub(crate) fn load_trusted_address(
    storage: &dyn Storage,
    chain: &ChainName,
) -> Result<Address, Error> {
    TRUSTED_ITS_ADDRESSES
        .may_load(storage, chain)
        .map_err(Error::from)?
        .ok_or_else(|| Error::TrustedAddressNotFound(chain.clone()))
}

pub(crate) fn save_trusted_address(
    storage: &mut dyn Storage,
    chain: &ChainName,
    address: &Address,
) -> Result<(), Error> {
    TRUSTED_ITS_ADDRESSES
        .save(storage, chain, address)
        .map_err(Error::from)
}

pub(crate) fn remove_trusted_address(storage: &mut dyn Storage, chain: &ChainName) {
    TRUSTED_ITS_ADDRESSES.remove(storage, chain)
}

pub(crate) fn load_all_trusted_addresses(
    storage: &dyn Storage,
) -> Result<Vec<(ChainName, Address)>, Error> {
    TRUSTED_ITS_ADDRESSES
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;

    use super::*;

    #[test]
    fn config_storage() {
        let mut deps = mock_dependencies();

        // Test saving and loading config
        let config = Config {
            chain_name: "test-chain".parse().unwrap(),
            gateway: Addr::unchecked("gateway-address"),
        };

        assert!(save_config(deps.as_mut().storage, &config).is_ok());
        assert_eq!(load_config(deps.as_ref().storage).unwrap(), config);

        // Test missing config
        let deps = mock_dependencies();
        assert!(matches!(
            load_config(deps.as_ref().storage),
            Err(Error::MissingConfig)
        ));
    }

    #[test]
    fn trusted_addresses_storage() {
        let mut deps = mock_dependencies();

        let chain = "test-chain".parse().unwrap();
        let address: Address = "trusted-address".parse().unwrap();

        // Test saving and loading trusted address
        assert!(save_trusted_address(deps.as_mut().storage, &chain, &address).is_ok());
        assert_eq!(
            load_trusted_address(deps.as_ref().storage, &chain).unwrap(),
            address
        );

        // Test removing trusted address
        remove_trusted_address(deps.as_mut().storage, &chain);
        assert!(matches!(
            load_trusted_address(deps.as_ref().storage, &chain),
            Err(Error::TrustedAddressNotFound(_))
        ));

        // Test getting all trusted addresses
        let chain1 = "chain1".parse().unwrap();
        let chain2 = "chain2".parse().unwrap();
        let address1: Address = "address1".parse().unwrap();
        let address2: Address = "address2".parse().unwrap();
        assert!(save_trusted_address(deps.as_mut().storage, &chain1, &address1).is_ok());
        assert!(save_trusted_address(deps.as_mut().storage, &chain2, &address2).is_ok());

        let all_addresses = load_all_trusted_addresses(deps.as_ref().storage).unwrap();
        assert_eq!(all_addresses.len(), 2);
        assert!(all_addresses.contains(&(chain1, address1)));
        assert!(all_addresses.contains(&(chain2, address2)));
    }
}

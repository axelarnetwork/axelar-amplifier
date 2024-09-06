use std::collections::HashMap;

use axelar_wasm_std::IntoContractError;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{ensure, Addr, StdError, Storage};
use cw_storage_plus::{Item, Map};
use router_api::{Address, ChainName};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error("ITS contract got into an invalid state, its config is missing")]
    MissingConfig,
    #[error("its address for chain {0} not found")]
    ItsAddressNotFound(ChainName),
    #[error("its address for chain {0} already registered")]
    ItsAddressAlreadyRegistered(ChainName),
}

#[cw_serde]
pub struct Config {
    pub axelarnet_gateway: Addr,
}

const CONFIG: Item<Config> = Item::new("config");
const ITS_ADDRESSES: Map<&ChainName, Address> = Map::new("its_addresses");

pub fn load_config(storage: &dyn Storage) -> Config {
    CONFIG
        .load(storage)
        .expect("config must be set during instantiation")
}

pub fn save_config(storage: &mut dyn Storage, config: &Config) -> Result<(), Error> {
    Ok(CONFIG.save(storage, config)?)
}

pub fn may_load_its_address(
    storage: &dyn Storage,
    chain: &ChainName,
) -> Result<Option<Address>, Error> {
    Ok(ITS_ADDRESSES.may_load(storage, chain)?)
}

pub fn load_its_address(storage: &dyn Storage, chain: &ChainName) -> Result<Address, Error> {
    may_load_its_address(storage, chain)?.ok_or_else(|| Error::ItsAddressNotFound(chain.clone()))
}

pub fn save_its_address(
    storage: &mut dyn Storage,
    chain: &ChainName,
    address: &Address,
) -> Result<(), Error> {
    ensure!(may_load_its_address(storage, chain)?.is_none(), Error::ItsAddressAlreadyRegistered(chain.clone()));

    Ok(ITS_ADDRESSES.save(storage, chain, address)?)
}

pub fn remove_its_address(storage: &mut dyn Storage, chain: &ChainName) {
    ITS_ADDRESSES.remove(storage, chain)
}

pub fn load_all_its_addresses(storage: &dyn Storage) -> Result<HashMap<ChainName, Address>, Error> {
    Ok(ITS_ADDRESSES
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .collect::<Result<HashMap<_, _>, _>>()?)
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
    use axelar_wasm_std::assert_err_contains;
    use cosmwasm_std::testing::mock_dependencies;

    use super::*;

    #[test]
    fn save_and_load_config_succeeds() {
        let mut deps = mock_dependencies();

        let config = Config {
            axelarnet_gateway: Addr::unchecked("gateway-address"),
        };

        assert_ok!(save_config(deps.as_mut().storage, &config));
        assert_eq!(load_config(deps.as_ref().storage), config);
    }

    #[test]
    #[should_panic(expected = "config must be set during instantiation")]
    fn load_missing_config_fails() {
        let deps = mock_dependencies();
        load_config(deps.as_ref().storage);
    }

    #[test]
    fn save_and_load_its_address_succeeds() {
        let mut deps = mock_dependencies();

        let chain1 = "chain1".parse().unwrap();
        let chain2 = "chain2".parse().unwrap();
        let address1: Address = "address1".parse().unwrap();
        let address2: Address = "address2".parse().unwrap();

        assert_err_contains!(
            load_its_address(deps.as_ref().storage, &chain1),
            Error,
            Error::ItsAddressNotFound(its_chain) if its_chain == &chain1
        );
        assert_eq!(
            assert_ok!(load_all_its_addresses(deps.as_ref().storage)),
            HashMap::new()
        );

        assert_ok!(save_its_address(deps.as_mut().storage, &chain1, &address1));
        assert_ok!(save_its_address(deps.as_mut().storage, &chain2, &address2));
        assert_eq!(
            assert_ok!(load_its_address(deps.as_ref().storage, &chain1)),
            address1
        );
        assert_eq!(
            assert_ok!(load_its_address(deps.as_ref().storage, &chain2)),
            address2
        );

        let all_addresses = assert_ok!(load_all_its_addresses(deps.as_ref().storage));
        assert_eq!(
            all_addresses,
            [(chain1, address1), (chain2, address2)]
                .into_iter()
                .collect::<HashMap<_, _>>()
        );
    }
}
use cosmwasm_std::{to_json_binary, Binary, Deps};
use router_api::ChainName;

use crate::msg::{AllTrustedAddressesResponse, TrustedAddressResponse};
use crate::state;

pub fn trusted_address(deps: Deps, chain: ChainName) -> Result<Binary, state::Error> {
    let address = state::load_trusted_address(deps.storage, &chain).ok();
    to_json_binary(&TrustedAddressResponse { address }).map_err(state::Error::from)
}

pub fn all_trusted_addresses(deps: Deps) -> Result<Binary, state::Error> {
    let addresses = state::load_all_trusted_addresses(deps.storage)?
        .into_iter()
        .collect();
    to_json_binary(&AllTrustedAddressesResponse { addresses }).map_err(state::Error::from)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::from_json;
    use cosmwasm_std::testing::mock_dependencies;
    use router_api::Address;

    use super::*;
    use crate::state::save_trusted_address;

    #[test]
    fn query_trusted_address() {
        let mut deps = mock_dependencies();

        let chain: ChainName = "test-chain".parse().unwrap();
        let address: Address = "trusted-address".parse().unwrap();

        // Save a trusted address
        save_trusted_address(deps.as_mut().storage, &chain, &address).unwrap();

        // Query the trusted address
        let bin = trusted_address(deps.as_ref(), chain).unwrap();
        let res: TrustedAddressResponse = from_json(bin).unwrap();
        assert_eq!(res.address, Some(address));

        // Query a non-existent trusted address
        let non_existent_chain: ChainName = "non-existent-chain".parse().unwrap();
        let bin = trusted_address(deps.as_ref(), non_existent_chain).unwrap();
        let res: TrustedAddressResponse = from_json(bin).unwrap();
        assert_eq!(res.address, None);
    }

    #[test]
    fn query_all_trusted_addresses() {
        let mut deps = mock_dependencies();

        let chain1: ChainName = "chain1".parse().unwrap();
        let address1: Address = "address1".parse().unwrap();
        let chain2: ChainName = "chain2".parse().unwrap();
        let address2: Address = "address2".parse().unwrap();

        // Save trusted addresses
        save_trusted_address(deps.as_mut().storage, &chain1, &address1).unwrap();
        save_trusted_address(deps.as_mut().storage, &chain2, &address2).unwrap();

        // Query all trusted addresses
        let bin = all_trusted_addresses(deps.as_ref()).unwrap();
        let res: AllTrustedAddressesResponse = from_json(bin).unwrap();
        assert_eq!(res.addresses.len(), 2);
        assert_eq!(res.addresses.get(&chain1), Some(&address1));
        assert_eq!(res.addresses.get(&chain2), Some(&address2));
    }
}

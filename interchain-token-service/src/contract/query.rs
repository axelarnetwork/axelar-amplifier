use cosmwasm_std::{to_json_binary, Binary, Deps};
use router_api::ChainName;

use crate::state;

pub fn its_address(deps: Deps, chain: ChainName) -> Result<Binary, state::Error> {
    let address = state::may_load_its_address(deps.storage, &chain)?;
    Ok(to_json_binary(&address)?)
}

pub fn all_its_addresses(deps: Deps) -> Result<Binary, state::Error> {
    let addresses = state::load_all_its_addresses(deps.storage)?;
    Ok(to_json_binary(&addresses)?)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axelar_wasm_std::FnExt;
    use cosmwasm_std::from_json;
    use cosmwasm_std::testing::mock_dependencies;
    use router_api::Address;

    use super::*;
    use crate::state::save_its_address;

    #[test]
    fn query_trusted_address() {
        let mut deps = mock_dependencies();

        let chain: ChainName = "test-chain".parse().unwrap();
        let address: Address = "trusted-address".parse().unwrap();

        // Save a trusted address
        save_its_address(deps.as_mut().storage, &chain, &address).unwrap();

        // Query the trusted address
        let bin = its_address(deps.as_ref(), chain).unwrap();
        let res: Option<Address> = from_json(bin).unwrap();
        assert_eq!(res, Some(address));

        // Query a non-existent trusted address
        let non_existent_chain: ChainName = "non-existent-chain".parse().unwrap();
        let bin = its_address(deps.as_ref(), non_existent_chain).unwrap();
        let res: Option<Address> = from_json(bin).unwrap();
        assert_eq!(res, None);
    }

    #[test]
    fn query_all_trusted_addresses() {
        let mut deps = mock_dependencies();

        let chain1: ChainName = "chain1".parse().unwrap();
        let address1: Address = "address1".parse().unwrap();
        let chain2: ChainName = "chain2".parse().unwrap();
        let address2: Address = "address2".parse().unwrap();

        // Save trusted addresses
        save_its_address(deps.as_mut().storage, &chain1, &address1).unwrap();
        save_its_address(deps.as_mut().storage, &chain2, &address2).unwrap();

        // Query all trusted addresses
        let addresses: HashMap<ChainName, Address> = all_its_addresses(deps.as_ref())
            .unwrap()
            .then(from_json)
            .unwrap();
        assert_eq!(
            addresses,
            vec![(chain1, address1), (chain2, address2)]
                .into_iter()
                .collect::<HashMap<_, _>>()
        );
    }
}

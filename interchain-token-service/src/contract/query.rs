use cosmwasm_std::{to_json_binary, Binary, Deps};
use router_api::ChainName;

use crate::msg::{AllTrustedAddressesResponse, TokenBalanceResponse, TrustedAddressResponse};
use crate::{state, TokenId};

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

pub fn token_balance(
    deps: Deps,
    chain: ChainName,
    token_id: TokenId,
) -> Result<Binary, state::Error> {
    let balance = state::may_load_token_balance(deps.storage, &token_id, &chain)?;
    to_json_binary(&TokenBalanceResponse { balance }).map_err(state::Error::from)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{from_json, Uint256};
    use router_api::Address;
    use state::TokenBalance;

    use super::*;
    use crate::state::{save_trusted_address, start_token_balance, update_token_balance};

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

    #[test]
    fn query_token_balance() {
        let mut deps = mock_dependencies();

        let chain: ChainName = "test-chain".parse().unwrap();
        let token_id = TokenId::new([1u8; 32]);

        // Start balance tracking for the token
        start_token_balance(deps.as_mut().storage, token_id.clone(), chain.clone(), true).unwrap();

        // Query the balance (should be zero)
        let bin = token_balance(deps.as_ref(), chain.clone(), token_id.clone()).unwrap();
        let res: TokenBalanceResponse = from_json(bin).unwrap();
        assert_eq!(res.balance, Some(TokenBalance::Tracked(Uint256::zero())));

        // Update the balance
        let amount = Uint256::from(1000u128);
        update_token_balance(
            deps.as_mut().storage,
            token_id.clone(),
            chain.clone(),
            amount,
            true,
        )
        .unwrap();

        // Query the updated balance
        let bin = token_balance(deps.as_ref(), chain.clone(), token_id).unwrap();
        let res: TokenBalanceResponse = from_json(bin).unwrap();
        assert_eq!(res.balance, Some(TokenBalance::Tracked(amount)));

        // Query a non-existent token balance
        let non_existent_token_id = TokenId::new([2u8; 32]);
        let bin = token_balance(deps.as_ref(), chain.clone(), non_existent_token_id).unwrap();
        let res: TokenBalanceResponse = from_json(bin).unwrap();
        assert_eq!(res.balance, None);

        // Start untracked balance for a new token
        let untracked_token_id = TokenId::new([3u8; 32]);
        start_token_balance(
            deps.as_mut().storage,
            untracked_token_id.clone(),
            chain.clone(),
            false,
        )
        .unwrap();

        // Query the untracked balance
        let bin = token_balance(deps.as_ref(), chain, untracked_token_id).unwrap();
        let res: TokenBalanceResponse = from_json(bin).unwrap();
        assert_eq!(res.balance, Some(TokenBalance::Untracked));
    }
}

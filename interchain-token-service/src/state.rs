use axelar_wasm_std::{FnExt, IntoContractError};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, StdError, StdResult, Storage, Uint256};
use cw_storage_plus::{Item, Key, KeyDeserialize, Map, Prefixer, PrimaryKey};
use router_api::{Address, ChainName, ChainNameRaw};

use crate::TokenId;

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error("ITS contract got into an invalid state, its config is missing")]
    MissingConfig,
    #[error("trusted address for chain {0} not found")]
    TrustedAddressNotFound(ChainName),
    #[error("insufficient balance for token {token_id} on chain {chain}")]
    InsufficientBalance {
        token_id: TokenId,
        chain: ChainName,
        balance: Uint256,
    },
    #[error("token {token_id} is already registered on chain {chain}")]
    TokenAlreadyRegistered { token_id: TokenId, chain: ChainName },
}

#[cw_serde]
pub struct Config {
    pub chain_name: ChainNameRaw,
    pub gateway: Addr,
}

/// Token balance for a given token id and chain
#[cw_serde]
pub enum TokenBalance {
    /// Token balance is tracked on the chain
    Tracked(Uint256),
    /// Token balance is not tracked
    Untracked,
}

#[cw_serde]
pub struct TokenChainPair {
    pub token_id: TokenId,
    pub chain: ChainName,
}

impl<'a> PrimaryKey<'a> for TokenChainPair {
    type Prefix = TokenId;
    type SubPrefix = ();
    type Suffix = ChainName;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        let mut keys = self.token_id.key();
        keys.extend(self.chain.key());
        keys
    }
}

impl<'a> Prefixer<'a> for TokenChainPair {
    fn prefix(&self) -> Vec<Key> {
        self.key()
    }
}

impl KeyDeserialize for TokenChainPair {
    type Output = Self;

    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        if value.len() < 32 {
            return Err(StdError::generic_err("Invalid key length"));
        }
        let (token_id_bytes, chain_bytes) = value.split_at(32);
        let token_id = TokenId::new(
            token_id_bytes
                .try_into()
                .map_err(|_| StdError::generic_err("Invalid TokenId"))?,
        );
        let chain = ChainName::from_vec(chain_bytes.to_vec())?;

        Ok(TokenChainPair { token_id, chain })
    }
}

const CONFIG: Item<Config> = Item::new("config");
const TRUSTED_ITS_ADDRESSES: Map<&ChainName, Address> = Map::new("trusted_its_addresses");
const TOKEN_BALANCES: Map<TokenChainPair, TokenBalance> = Map::new("token_balances");

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

#[cfg(test)]
pub(crate) fn remove_trusted_address(
    storage: &mut dyn Storage,
    chain: &ChainName,
) -> Result<(), Error> {
    TRUSTED_ITS_ADDRESSES.remove(storage, chain);
    Ok(())
}

pub(crate) fn load_all_trusted_addresses(
    storage: &dyn Storage,
) -> Result<Vec<(ChainName, Address)>, Error> {
    TRUSTED_ITS_ADDRESSES
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::from)
}

pub fn start_token_balance(
    storage: &mut dyn Storage,
    token_id: TokenId,
    chain: ChainName,
    track_balance: bool,
) -> Result<(), Error> {
    let key = TokenChainPair { token_id, chain };

    match TOKEN_BALANCES.may_load(storage, key.clone())? {
        None => {
            let initial_balance = if track_balance {
                TokenBalance::Tracked(Uint256::zero())
            } else {
                TokenBalance::Untracked
            };

            TOKEN_BALANCES
                .save(storage, key, &initial_balance)?
                .then(Ok)
        }
        Some(_) => Err(Error::TokenAlreadyRegistered {
            token_id: key.token_id,
            chain: key.chain,
        }),
    }
}

pub fn update_token_balance(
    storage: &mut dyn Storage,
    token_id: TokenId,
    chain: ChainName,
    amount: Uint256,
    is_deposit: bool,
) -> Result<(), Error> {
    let key = TokenChainPair { token_id, chain };

    let token_balance = TOKEN_BALANCES.may_load(storage, key.clone())?;

    match token_balance {
        Some(TokenBalance::Tracked(balance)) => {
            let token_balance = if is_deposit {
                balance
                    .checked_add(amount)
                    .map_err(|_| Error::MissingConfig)?
            } else {
                balance
                    .checked_sub(amount)
                    .map_err(|_| Error::MissingConfig)?
            }
            .then(TokenBalance::Tracked);

            TOKEN_BALANCES.save(storage, key.clone(), &token_balance)?;
        }
        Some(_) | None => (),
    }

    Ok(())
}

pub fn may_load_token_balance(
    storage: &dyn Storage,
    token_id: &TokenId,
    chain: &ChainName,
) -> Result<Option<TokenBalance>, Error> {
    let key = TokenChainPair {
        token_id: token_id.clone(),
        chain: chain.clone(),
    };

    TOKEN_BALANCES.may_load(storage, key)?.then(Ok)
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
        assert!(remove_trusted_address(deps.as_mut().storage, &chain).is_ok());
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

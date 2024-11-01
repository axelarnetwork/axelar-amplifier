use std::collections::HashMap;

use axelar_wasm_std::{nonempty, FnExt, IntoContractError};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{ensure, Addr, OverflowError, StdError, Storage, Uint256};
use cw_storage_plus::{Item, Map};
use router_api::{Address, ChainNameRaw};

use crate::{Message, TokenId};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error(transparent)]
    Std(#[from] StdError),
    #[error("its address for chain {0} not found")]
    ItsContractNotFound(ChainNameRaw),
    #[error("its address for chain {0} already registered")]
    ItsContractAlreadyRegistered(ChainNameRaw),
}

#[cw_serde]
pub struct Config {
    pub axelarnet_gateway: Addr,
}

#[cw_serde]
pub struct ChainConfig {
    max_uint: nonempty::Uint256,
    max_target_decimals: u8,
}

#[cw_serde]
pub enum TokenBalance {
    /// The total token balance bridged to this chain.
    /// ITS Hub will not allow bridging back more than this amount of the token from the corresponding chain.
    Tracked(Uint256),
    /// The token balance bridged to this chain is not tracked.
    Untracked,
}

#[cw_serde]
pub struct TokenInfo {
    pub balance: TokenBalance,
}

#[derive(Clone)]
pub enum DirectionalChain {
    Source(ChainNameRaw),
    Destination(ChainNameRaw),
}

/// The deployment type of the token.
pub enum TokenDeploymentType {
    /// The token is trustless.
    Trustless,
    /// The token has a custom minter.
    CustomMinter,
}

impl From<DirectionalChain> for ChainNameRaw {
    fn from(directional_chain: DirectionalChain) -> Self {
        match directional_chain {
            DirectionalChain::Source(chain) => chain,
            DirectionalChain::Destination(chain) => chain,
        }
    }
}

const CONFIG: Item<Config> = Item::new("config");
const ITS_CONTRACTS: Map<&ChainNameRaw, Address> = Map::new("its_contracts");
const CHAIN_CONFIGS: Map<&ChainNameRaw, ChainConfig> = Map::new("chain_configs");
const TOKEN_INFO: Map<&(ChainNameRaw, TokenId), TokenInfo> = Map::new("token_info");

pub fn load_config(storage: &dyn Storage) -> Config {
    CONFIG
        .load(storage)
        .expect("config must be set during instantiation")
}

pub fn save_config(storage: &mut dyn Storage, config: &Config) -> Result<(), Error> {
    Ok(CONFIG.save(storage, config)?)
}

pub fn may_load_chain_config(
    storage: &dyn Storage,
    chain: &ChainNameRaw,
) -> Result<Option<ChainConfig>, Error> {
    Ok(CHAIN_CONFIGS.may_load(storage, chain)?)
}

pub fn save_chain_config(
    storage: &mut dyn Storage,
    chain: &ChainNameRaw,
    max_uint: nonempty::Uint256,
    max_target_decimals: u8,
) -> Result<(), Error> {
    Ok(CHAIN_CONFIGS.save(
        storage,
        chain,
        &ChainConfig {
            max_uint,
            max_target_decimals,
        },
    )?)
}

pub fn may_load_its_contract(
    storage: &dyn Storage,
    chain: &ChainNameRaw,
) -> Result<Option<Address>, Error> {
    Ok(ITS_CONTRACTS.may_load(storage, chain)?)
}

pub fn load_its_contract(storage: &dyn Storage, chain: &ChainNameRaw) -> Result<Address, Error> {
    may_load_its_contract(storage, chain)?.ok_or_else(|| Error::ItsContractNotFound(chain.clone()))
}

pub fn save_its_contract(
    storage: &mut dyn Storage,
    chain: &ChainNameRaw,
    address: &Address,
) -> Result<(), Error> {
    ensure!(
        may_load_its_contract(storage, chain)?.is_none(),
        Error::ItsContractAlreadyRegistered(chain.clone())
    );

    Ok(ITS_CONTRACTS.save(storage, chain, address)?)
}

pub fn remove_its_contract(storage: &mut dyn Storage, chain: &ChainNameRaw) -> Result<(), Error> {
    ensure!(
        may_load_its_contract(storage, chain)?.is_some(),
        Error::ItsContractNotFound(chain.clone())
    );

    ITS_CONTRACTS.remove(storage, chain);

    Ok(())
}

pub fn load_all_its_contracts(
    storage: &dyn Storage,
) -> Result<HashMap<ChainNameRaw, Address>, Error> {
    Ok(ITS_CONTRACTS
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .collect::<Result<HashMap<_, _>, _>>()?)
}

pub fn save_token_info(
    storage: &mut dyn Storage,
    chain: ChainNameRaw,
    token_id: TokenId,
    token_info: TokenInfo,
) -> Result<(), Error> {
    Ok(TOKEN_INFO.save(storage, &(chain, token_id), &token_info)?)
}

pub fn may_load_token_info(
    storage: &dyn Storage,
    chain: ChainNameRaw,
    token_id: TokenId,
) -> Result<Option<TokenInfo>, Error> {
    Ok(TOKEN_INFO.may_load(storage, &(chain, token_id))?)
}

impl TokenBalance {
    fn checked_add(&self, amount: nonempty::Uint256) -> Result<Self, OverflowError> {
        match self {
            TokenBalance::Tracked(balance) => {
                TokenBalance::Tracked(balance.checked_add(amount.into())?)
            }
            TokenBalance::Untracked => TokenBalance::Untracked,
        }
        .then(Ok)
    }

    fn checked_sub(&self, amount: nonempty::Uint256) -> Result<Self, OverflowError> {
        match self {
            TokenBalance::Tracked(balance) => {
                TokenBalance::Tracked(balance.checked_sub(amount.into())?)
            }
            TokenBalance::Untracked => TokenBalance::Untracked,
        }
        .then(Ok)
    }
}

impl TokenInfo {
    pub fn update_balance(
        &mut self,
        amount: nonempty::Uint256,
        directional_chain: DirectionalChain,
    ) -> Result<(), OverflowError> {
        self.balance = match directional_chain {
            DirectionalChain::Source(_) => self.balance.checked_sub(amount)?,
            DirectionalChain::Destination(_) => self.balance.checked_add(amount)?,
        };

        Ok(())
    }
}

impl From<(&DirectionalChain, TokenDeploymentType)> for TokenBalance {
    fn from(
        (directional_chain, token_deployment_type): (&DirectionalChain, TokenDeploymentType),
    ) -> Self {
        match (directional_chain, token_deployment_type) {
            // Token balances are tracked for remote trustless tokens
            (DirectionalChain::Destination(_), TokenDeploymentType::Trustless) => {
                TokenBalance::Tracked(Uint256::zero())
            }
            _ => TokenBalance::Untracked,
        }
    }
}

impl From<&Message> for Option<TokenDeploymentType> {
    fn from(message: &Message) -> Self {
        match message {
            Message::InterchainTransfer { .. } => None,
            Message::DeployInterchainToken { minter: None, .. } => {
                Some(TokenDeploymentType::Trustless)
            }
            _ => Some(TokenDeploymentType::CustomMinter),
        }
    }
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
    fn save_and_load_its_contract_succeeds() {
        let mut deps = mock_dependencies();

        let chain1 = "chain1".parse().unwrap();
        let chain2: ChainNameRaw = "chain2".parse().unwrap();
        let address1: Address = "address1".parse().unwrap();
        let address2: Address = "address2".parse().unwrap();

        assert_err_contains!(
            load_its_contract(deps.as_ref().storage, &chain1),
            Error,
            Error::ItsContractNotFound(its_chain) if its_chain == &chain1
        );
        assert_eq!(
            assert_ok!(load_all_its_contracts(deps.as_ref().storage)),
            HashMap::new()
        );

        assert_ok!(save_its_contract(deps.as_mut().storage, &chain1, &address1));
        assert_ok!(save_its_contract(deps.as_mut().storage, &chain2, &address2));
        assert_eq!(
            assert_ok!(load_its_contract(deps.as_ref().storage, &chain1)),
            address1
        );
        assert_eq!(
            assert_ok!(load_its_contract(deps.as_ref().storage, &chain2)),
            address2
        );

        let all_addresses = assert_ok!(load_all_its_contracts(deps.as_ref().storage));
        assert_eq!(
            all_addresses,
            [(chain1, address1), (chain2, address2)]
                .into_iter()
                .collect::<HashMap<_, _>>()
        );
    }
}

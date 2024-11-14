use std::collections::HashMap;

use axelar_wasm_std::{nonempty, FnExt, IntoContractError};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, OverflowError, StdError, Storage, Uint256};
use cw_storage_plus::{Item, Map};
use error_stack::{report, Result, ResultExt};
use router_api::{Address, ChainNameRaw};

use crate::{msg, TokenId};

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("ITS contract got into an invalid state, its config is missing")]
    MissingConfig,
    #[error("its address for chain {0} not found")]
    ItsContractNotFound(ChainNameRaw),
    #[error("its address for chain {0} already registered")]
    ItsContractAlreadyRegistered(ChainNameRaw),
    #[error("chain not found {0}")]
    ChainNotFound(ChainNameRaw),
    #[error("chain config for chain {0} not found")]
    ChainConfigNotFound(ChainNameRaw),
    // This is a generic error to use when cw_storage_plus returns an error that is unexpected and
    // should never happen, such as an error encountered when saving data.
    #[error("storage error")]
    Storage,
}

#[cw_serde]
pub struct Config {
    pub axelarnet_gateway: Addr,
}

#[cw_serde]
pub struct ChainConfig {
    pub truncation: TruncationConfig,
    pub its_address: Address,
    frozen: bool,
}

#[cw_serde]
pub struct TruncationConfig {
    pub max_uint: nonempty::Uint256, // The maximum uint value that is supported by the chain's token standard
    pub max_decimals_when_truncating: u8, // The maximum number of decimals that is preserved when deploying from a chain with a larger max_uint
}

impl From<msg::ChainConfig> for ChainConfig {
    fn from(value: msg::ChainConfig) -> Self {
        Self {
            truncation: TruncationConfig {
                max_uint: value.truncation.max_uint,
                max_decimals_when_truncating: value.truncation.max_decimals_when_truncating,
            },
            its_address: value.its_edge_contract,
            frozen: false,
        }
    }
}

#[cw_serde]
pub enum TokenSupply {
    /// The total token supply bridged to this chain.
    /// ITS Hub will not allow bridging back more than this amount of the token from the corresponding chain.
    Tracked(Uint256),
    /// The token supply bridged to this chain is not tracked.
    Untracked,
}

impl TokenSupply {
    pub fn checked_add(self, amount: nonempty::Uint256) -> Result<Self, OverflowError> {
        match self {
            TokenSupply::Untracked => TokenSupply::Untracked,
            TokenSupply::Tracked(supply) => {
                TokenSupply::Tracked(supply.checked_add(amount.into())?)
            }
        }
        .then(Ok)
    }
    pub fn checked_sub(self, amount: nonempty::Uint256) -> Result<Self, OverflowError> {
        match self {
            TokenSupply::Untracked => TokenSupply::Untracked,
            TokenSupply::Tracked(supply) => {
                TokenSupply::Tracked(supply.checked_sub(amount.into())?)
            }
        }
        .then(Ok)
    }
}

/// Information about a token on a specific chain.
#[cw_serde]
pub struct TokenInstance {
    pub supply: TokenSupply,
    pub decimals: u8,
}

impl TokenInstance {
    pub fn new_on_origin(decimals: u8) -> Self {
        Self {
            supply: TokenSupply::Untracked,
            decimals,
        }
    }

    pub fn new(deployment_type: &TokenDeploymentType, decimals: u8) -> Self {
        let supply = match deployment_type {
            TokenDeploymentType::Trustless => TokenSupply::Tracked(Uint256::zero()),
            _ => TokenSupply::Untracked,
        };

        Self { supply, decimals }
    }
}

/// The deployment type of the token.
pub enum TokenDeploymentType {
    /// The token is trustless, i.e. only owned by ITS.
    Trustless,
    /// The token has a custom minter.
    CustomMinter,
}

#[cw_serde]
pub struct TokenConfig {
    pub origin_chain: ChainNameRaw,
}

const CONFIG: Item<Config> = Item::new("config");
const CHAIN_CONFIGS: Map<&ChainNameRaw, ChainConfig> = Map::new("chain_configs");
const TOKEN_INSTANCE: Map<&(ChainNameRaw, TokenId), TokenInstance> = Map::new("token_instance");
const TOKEN_CONFIGS: Map<&TokenId, TokenConfig> = Map::new("token_configs");

pub fn load_config(storage: &dyn Storage) -> Config {
    CONFIG
        .load(storage)
        .expect("config must be set during instantiation")
}

pub fn save_config(storage: &mut dyn Storage, config: &Config) -> Result<(), Error> {
    CONFIG.save(storage, config).change_context(Error::Storage)
}

pub fn may_load_chain_config(
    storage: &dyn Storage,
    chain: &ChainNameRaw,
) -> Result<Option<ChainConfig>, Error> {
    CHAIN_CONFIGS
        .may_load(storage, chain)
        .change_context(Error::Storage)
}

pub fn load_chain_config(
    storage: &dyn Storage,
    chain: &ChainNameRaw,
) -> Result<ChainConfig, Error> {
    may_load_chain_config(storage, chain)
        .change_context(Error::Storage)?
        .ok_or_else(|| report!(Error::ChainNotFound(chain.to_owned())))
}

pub fn save_chain_config(
    storage: &mut dyn Storage,
    chain: &ChainNameRaw,
    config: impl Into<ChainConfig>,
) -> Result<(), Error> {
    CHAIN_CONFIGS
        .save(storage, chain, &config.into())
        .change_context(Error::Storage)
}

pub fn update_its_contract(
    storage: &mut dyn Storage,
    chain: &ChainNameRaw,
    its_address: Address,
) -> Result<ChainConfig, Error> {
    CHAIN_CONFIGS
        .update(storage, chain, |config| match config {
            Some(config) => Ok(ChainConfig {
                its_address,
                ..config
            }),
            None => Err(StdError::not_found("config not found")),
        })
        .change_context(Error::ChainNotFound(chain.to_owned()))
}

pub fn may_load_its_contract(
    storage: &dyn Storage,
    chain: &ChainNameRaw,
) -> Result<Option<Address>, Error> {
    CHAIN_CONFIGS
        .may_load(storage, chain)
        .map(|res| res.map(|config| config.its_address))
        .change_context(Error::Storage)
}

pub fn load_its_contract(storage: &dyn Storage, chain: &ChainNameRaw) -> Result<Address, Error> {
    may_load_its_contract(storage, chain)
        .change_context(Error::Storage)?
        .ok_or_else(|| report!(Error::ItsContractNotFound(chain.clone())))
}

pub fn load_all_its_contracts(
    storage: &dyn Storage,
) -> Result<HashMap<ChainNameRaw, Address>, Error> {
    CHAIN_CONFIGS
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .map(|res| {
            res.map(|(chain, config)| (chain, config.its_address))
                .change_context(Error::Storage)
        })
        .collect::<Result<HashMap<_, _>, _>>()
}

pub fn is_chain_frozen(storage: &dyn Storage, chain: &ChainNameRaw) -> Result<bool, Error> {
    CHAIN_CONFIGS
        .load(storage, chain)
        .change_context(Error::ChainNotFound(chain.to_owned()))
        .map(|chain_config| chain_config.frozen)
}

pub fn freeze_chain(storage: &mut dyn Storage, chain: &ChainNameRaw) -> Result<ChainConfig, Error> {
    CHAIN_CONFIGS
        .update(storage, chain, |elt| match elt {
            Some(x) => Ok(ChainConfig { frozen: true, ..x }),
            None => Err(StdError::not_found("chain not found".to_string())),
        })
        .change_context(Error::ChainNotFound(chain.to_owned()))
}

pub fn unfreeze_chain(
    storage: &mut dyn Storage,
    chain: &ChainNameRaw,
) -> Result<ChainConfig, Error> {
    CHAIN_CONFIGS
        .update(storage, chain, |elt| match elt {
            Some(x) => Ok(ChainConfig { frozen: false, ..x }),
            None => Err(StdError::not_found("chain not found".to_string())),
        })
        .change_context(Error::ChainNotFound(chain.to_owned()))
}

pub fn save_token_instance(
    storage: &mut dyn Storage,
    chain: ChainNameRaw,
    token_id: TokenId,
    token_instance: &TokenInstance,
) -> Result<(), Error> {
    TOKEN_INSTANCE
        .save(storage, &(chain, token_id), token_instance)
        .change_context(Error::Storage)
}

pub fn may_load_token_instance(
    storage: &dyn Storage,
    chain: ChainNameRaw,
    token_id: TokenId,
) -> Result<Option<TokenInstance>, Error> {
    TOKEN_INSTANCE
        .may_load(storage, &(chain, token_id))
        .change_context(Error::Storage)
}

pub fn may_load_token_config(
    storage: &dyn Storage,
    token_id: &TokenId,
) -> Result<Option<TokenConfig>, Error> {
    TOKEN_CONFIGS
        .may_load(storage, token_id)
        .change_context(Error::Storage)
}

pub fn save_token_config(
    storage: &mut dyn Storage,
    token_id: TokenId,
    token_config: &TokenConfig,
) -> Result<(), Error> {
    TOKEN_CONFIGS
        .save(storage, &token_id, token_config)
        .change_context(Error::Storage)
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

        assert_ok!(save_chain_config(
            deps.as_mut().storage,
            &chain1.clone(),
            msg::ChainConfig {
                chain: chain1.clone(),
                its_edge_contract: address1.clone(),
                truncation: msg::TruncationConfig {
                    max_uint: Uint256::MAX.try_into().unwrap(),
                    max_decimals_when_truncating: 16u8
                }
            }
        ));
        assert_ok!(save_chain_config(
            deps.as_mut().storage,
            &chain2.clone(),
            msg::ChainConfig {
                chain: chain2.clone(),
                its_edge_contract: address2.clone(),
                truncation: msg::TruncationConfig {
                    max_uint: Uint256::MAX.try_into().unwrap(),
                    max_decimals_when_truncating: 16u8
                }
            }
        ));
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

use std::collections::{HashMap, HashSet};

use axelar_wasm_std::address::validate_cosmwasm_address;
use axelar_wasm_std::{migrate_from_version, IntoContractError};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, Response, Storage};
use cw_storage_plus::Map;
use error_stack::ResultExt;
use router_api::{Address, ChainNameRaw};

use crate::shared::NumBits;
use crate::state::{save_chain_config, ChainConfig as NewChainConfig};

// Old state structure (before migration)
#[cw_serde]
pub struct OldTruncationConfig {
    pub max_uint_bits: NumBits,
    pub max_decimals_when_truncating: u8,
}

#[cw_serde]
pub struct OldChainConfig {
    pub truncation: OldTruncationConfig,
    pub its_address: Address,
    pub frozen: bool,
    // Note: no translation_contract field in old state
}

// Storage map for old chain configs
const OLD_CHAIN_CONFIGS: Map<&ChainNameRaw, OldChainConfig> = Map::new("chain_configs");

#[cw_serde]
pub struct ChainTranslationConfig {
    pub chain: ChainNameRaw,
    pub translation_contract: Address,
}

#[cw_serde]
pub struct MigrateMsg {
    /// List of chain and translation contract address pairs
    pub chain_translation_configs: Vec<ChainTranslationConfig>,
}

fn load_old_chain_config(
    storage: &dyn Storage,
    chain: &ChainNameRaw,
) -> Result<OldChainConfig, cosmwasm_std::StdError> {
    OLD_CHAIN_CONFIGS.load(storage, chain)
}

fn load_all_old_chain_configs(
    storage: &dyn Storage,
) -> Result<HashMap<ChainNameRaw, OldChainConfig>, cosmwasm_std::StdError> {
    OLD_CHAIN_CONFIGS
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .map(|res| res.map(|(chain, config)| (chain, config)))
        .collect::<Result<HashMap<_, _>, _>>()
}

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
    #[error("chain not found {0}")]
    ChainNotFound(ChainNameRaw),
    #[error("failed to load old chain configs")]
    LoadOldChainConfigs,
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.2")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    // Get all existing chains from old state format
    let existing_chains =
        load_all_old_chain_configs(deps.storage).change_context(Error::LoadOldChainConfigs)?;

    // Create a set of chains specified in the migration message
    let migration_chains: HashSet<ChainNameRaw> = msg
        .chain_translation_configs
        .iter()
        .map(|config| config.chain.clone())
        .collect();

    // Check that all existing chains are specified in the migration
    for existing_chain in existing_chains.keys() {
        if !migration_chains.contains(existing_chain) {
            return Err(Error::ChainNotFound(existing_chain.clone()).into());
        }
    }

    // Migrate each chain's config by loading old state and saving new state
    for chain_config in msg.chain_translation_configs {
        // Load the old chain config (without translation_contract)
        let old_chain_state = load_old_chain_config(deps.storage, &chain_config.chain)
            .change_context(Error::ChainNotFound(chain_config.chain.clone()))?;

        // Create new chain config with translation_contract added
        let new_chain_state = NewChainConfig {
            truncation: crate::state::TruncationConfig {
                max_uint_bits: old_chain_state.truncation.max_uint_bits,
                max_decimals_when_truncating: old_chain_state
                    .truncation
                    .max_decimals_when_truncating,
            },
            its_address: old_chain_state.its_address,
            frozen: old_chain_state.frozen,
            translation_contract: validate_cosmwasm_address(
                deps.api,
                &chain_config.translation_contract.to_string(),
            )?,
        };

        // Save the new chain config (this will overwrite the old format)
        save_chain_config(deps.storage, &chain_config.chain, &new_chain_state)?;
    }

    Ok(Response::new())
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::assert_err_contains;
    use cosmwasm_std::from_json;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, MockApi};

    use super::*;
    use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
    use crate::shared::NumBits;
    use crate::state::{load_chain_config, save_config, Config};

    type MockDeps = cosmwasm_std::OwnedDeps<
        cosmwasm_std::MemoryStorage,
        cosmwasm_std::testing::MockApi,
        cosmwasm_std::testing::MockQuerier<cosmwasm_std::Empty>,
    >;

    fn setup_test_chains_old_format(deps: &mut MockDeps) {
        // Set up contract version (normally done during instantiation)
        cw2::set_contract_version(&mut deps.storage, CONTRACT_NAME, CONTRACT_VERSION).unwrap();

        // Save config first
        let config = Config {
            axelarnet_gateway: MockApi::default().addr_make("gateway"),
            operator: MockApi::default().addr_make("operator"),
        };
        save_config(deps.as_mut().storage, &config).unwrap();

        // Setup test chains in OLD format (without translation_contract)
        let ethereum_chain = ChainNameRaw::try_from("ethereum").unwrap();
        let polygon_chain = ChainNameRaw::try_from("polygon").unwrap();

        let ethereum_config = OldChainConfig {
            truncation: OldTruncationConfig {
                max_uint_bits: NumBits::try_from(256u32).unwrap(),
                max_decimals_when_truncating: 18,
            },
            its_address: Address::try_from(
                MockApi::default().addr_make("ethereum_its").to_string(),
            )
            .unwrap(),
            frozen: false,
        };

        let polygon_config = OldChainConfig {
            truncation: OldTruncationConfig {
                max_uint_bits: NumBits::try_from(256u32).unwrap(),
                max_decimals_when_truncating: 18,
            },
            its_address: Address::try_from(MockApi::default().addr_make("polygon_its").to_string())
                .unwrap(),
            frozen: true, // Test with frozen chain
        };

        // Save in old format
        OLD_CHAIN_CONFIGS
            .save(deps.as_mut().storage, &ethereum_chain, &ethereum_config)
            .unwrap();
        OLD_CHAIN_CONFIGS
            .save(deps.as_mut().storage, &polygon_chain, &polygon_config)
            .unwrap();
    }

    #[test]
    fn test_migrate_success() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        setup_test_chains_old_format(&mut deps);

        let ethereum_translation = Address::try_from(
            MockApi::default()
                .addr_make("ethereum_translation")
                .to_string(),
        )
        .unwrap();
        let polygon_translation = Address::try_from(
            MockApi::default()
                .addr_make("polygon_translation")
                .to_string(),
        )
        .unwrap();

        let msg = MigrateMsg {
            chain_translation_configs: vec![
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("ethereum").unwrap(),
                    translation_contract: ethereum_translation.clone(),
                },
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("polygon").unwrap(),
                    translation_contract: polygon_translation.clone(),
                },
            ],
        };

        let result = migrate(deps.as_mut(), env, msg).unwrap();

        // Verify that translation contracts were added to the new format
        let ethereum_config = load_chain_config(
            deps.as_ref().storage,
            &ChainNameRaw::try_from("ethereum").unwrap(),
        )
        .unwrap();
        let polygon_config = load_chain_config(
            deps.as_ref().storage,
            &ChainNameRaw::try_from("polygon").unwrap(),
        )
        .unwrap();

        // Check ethereum config
        assert_eq!(
            ethereum_config.truncation.max_uint_bits,
            NumBits::try_from(256u32).unwrap()
        );
        assert_eq!(ethereum_config.truncation.max_decimals_when_truncating, 18);
        assert_eq!(
            ethereum_config.its_address,
            Address::try_from(MockApi::default().addr_make("ethereum_its").to_string()).unwrap()
        );
        assert_eq!(ethereum_config.frozen, false);
        assert_eq!(
            ethereum_config.translation_contract,
            MockApi::default().addr_make("ethereum_translation")
        );

        // Check polygon config
        assert_eq!(
            polygon_config.truncation.max_uint_bits,
            NumBits::try_from(256u32).unwrap()
        );
        assert_eq!(polygon_config.truncation.max_decimals_when_truncating, 18);
        assert_eq!(
            polygon_config.its_address,
            Address::try_from(MockApi::default().addr_make("polygon_its").to_string()).unwrap()
        );
        assert_eq!(polygon_config.frozen, true);
        assert_eq!(
            polygon_config.translation_contract,
            MockApi::default().addr_make("polygon_translation")
        );
    }

    #[test]
    fn test_migrate_fails_when_chain_missing_from_message() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        setup_test_chains_old_format(&mut deps);

        // Only provide one chain in migration message, but two exist in state
        let msg = MigrateMsg {
            chain_translation_configs: vec![
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("ethereum").unwrap(),
                    translation_contract: Address::try_from(
                        MockApi::default()
                            .addr_make("ethereum_translation")
                            .to_string(),
                    )
                    .unwrap(),
                },
                // Missing polygon chain
            ],
        };

        let result = migrate(deps.as_mut(), env, msg);
        assert!(result.is_err());
        assert_err_contains!(result, Error, ChainNotFound);
    }

    #[test]
    fn test_migrate_fails_when_chain_not_in_state() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        setup_test_chains_old_format(&mut deps);

        // Try to migrate a chain that doesn't exist in state
        let msg = MigrateMsg {
            chain_translation_configs: vec![
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("ethereum").unwrap(),
                    translation_contract: Address::try_from(
                        MockApi::default()
                            .addr_make("ethereum_translation")
                            .to_string(),
                    )
                    .unwrap(),
                },
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("polygon").unwrap(),
                    translation_contract: Address::try_from(
                        MockApi::default()
                            .addr_make("polygon_translation")
                            .to_string(),
                    )
                    .unwrap(),
                },
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("nonexistent").unwrap(),
                    translation_contract: Address::try_from(
                        MockApi::default()
                            .addr_make("nonexistent_translation")
                            .to_string(),
                    )
                    .unwrap(),
                },
            ],
        };

        let result = migrate(deps.as_mut(), env, msg);
        assert!(result.is_err());

        assert_err_contains!(result, Error, ChainNotFound);
    }

    #[test]
    fn test_migrate_single_chain() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // Set up contract version
        cw2::set_contract_version(&mut deps.storage, CONTRACT_NAME, CONTRACT_VERSION).unwrap();

        let config = Config {
            axelarnet_gateway: MockApi::default().addr_make("gateway"),
            operator: MockApi::default().addr_make("operator"),
        };
        save_config(deps.as_mut().storage, &config).unwrap();

        // Setup single test chain in OLD format
        let ethereum_chain = ChainNameRaw::try_from("ethereum").unwrap();
        let ethereum_config = OldChainConfig {
            truncation: OldTruncationConfig {
                max_uint_bits: NumBits::try_from(128u32).unwrap(),
                max_decimals_when_truncating: 6,
            },
            its_address: Address::try_from(
                MockApi::default().addr_make("ethereum_its").to_string(),
            )
            .unwrap(),
            frozen: false,
        };

        OLD_CHAIN_CONFIGS
            .save(deps.as_mut().storage, &ethereum_chain, &ethereum_config)
            .unwrap();

        let msg = MigrateMsg {
            chain_translation_configs: vec![ChainTranslationConfig {
                chain: ChainNameRaw::try_from("ethereum").unwrap(),
                translation_contract: Address::try_from(
                    MockApi::default()
                        .addr_make("ethereum_translation")
                        .to_string(),
                )
                .unwrap(),
            }],
        };

        let result = migrate(deps.as_mut(), env, msg).unwrap();

        // Verify the migrated config
        let migrated_config = load_chain_config(
            deps.as_ref().storage,
            &ChainNameRaw::try_from("ethereum").unwrap(),
        )
        .unwrap();
        assert_eq!(
            migrated_config.truncation.max_uint_bits,
            NumBits::try_from(128u32).unwrap()
        );
        assert_eq!(migrated_config.truncation.max_decimals_when_truncating, 6);
        assert_eq!(
            migrated_config.its_address,
            Address::try_from(MockApi::default().addr_make("ethereum_its").to_string()).unwrap()
        );
        assert_eq!(migrated_config.frozen, false);
        assert_eq!(
            migrated_config.translation_contract,
            MockApi::default().addr_make("ethereum_translation")
        );
    }

    #[test]
    fn test_migrate_preserves_different_truncation_configs() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // Set up contract version
        cw2::set_contract_version(&mut deps.storage, CONTRACT_NAME, CONTRACT_VERSION).unwrap();

        let config = Config {
            axelarnet_gateway: MockApi::default().addr_make("gateway"),
            operator: MockApi::default().addr_make("operator"),
        };
        save_config(deps.as_mut().storage, &config).unwrap();

        // Setup chains with different truncation configs
        let ethereum_chain = ChainNameRaw::try_from("ethereum").unwrap();
        let polygon_chain = ChainNameRaw::try_from("polygon").unwrap();

        let ethereum_config = OldChainConfig {
            truncation: OldTruncationConfig {
                max_uint_bits: NumBits::try_from(256u32).unwrap(),
                max_decimals_when_truncating: 18,
            },
            its_address: Address::try_from(
                MockApi::default().addr_make("ethereum_its").to_string(),
            )
            .unwrap(),
            frozen: false,
        };

        let polygon_config = OldChainConfig {
            truncation: OldTruncationConfig {
                max_uint_bits: NumBits::try_from(128u32).unwrap(),
                max_decimals_when_truncating: 6,
            },
            its_address: Address::try_from(MockApi::default().addr_make("polygon_its").to_string())
                .unwrap(),
            frozen: true,
        };

        OLD_CHAIN_CONFIGS
            .save(deps.as_mut().storage, &ethereum_chain, &ethereum_config)
            .unwrap();
        OLD_CHAIN_CONFIGS
            .save(deps.as_mut().storage, &polygon_chain, &polygon_config)
            .unwrap();

        let msg = MigrateMsg {
            chain_translation_configs: vec![
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("ethereum").unwrap(),
                    translation_contract: Address::try_from(
                        MockApi::default()
                            .addr_make("ethereum_translation")
                            .to_string(),
                    )
                    .unwrap(),
                },
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("polygon").unwrap(),
                    translation_contract: Address::try_from(
                        MockApi::default()
                            .addr_make("polygon_translation")
                            .to_string(),
                    )
                    .unwrap(),
                },
            ],
        };

        let result = migrate(deps.as_mut(), env, msg).unwrap();

        // Verify different truncation configs are preserved
        let ethereum_migrated = load_chain_config(
            deps.as_ref().storage,
            &ChainNameRaw::try_from("ethereum").unwrap(),
        )
        .unwrap();
        let polygon_migrated = load_chain_config(
            deps.as_ref().storage,
            &ChainNameRaw::try_from("polygon").unwrap(),
        )
        .unwrap();

        assert_eq!(
            ethereum_migrated.truncation.max_uint_bits,
            NumBits::try_from(256u32).unwrap()
        );
        assert_eq!(
            ethereum_migrated.truncation.max_decimals_when_truncating,
            18
        );
        assert_eq!(
            polygon_migrated.truncation.max_uint_bits,
            NumBits::try_from(128u32).unwrap()
        );
        assert_eq!(polygon_migrated.truncation.max_decimals_when_truncating, 6);
    }
}

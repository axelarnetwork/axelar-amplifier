use axelar_wasm_std::migrate_from_version;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, Response, Storage};
use cosmwasm_schema::cw_serde;
use router_api::{Address, ChainNameRaw};
use std::collections::HashSet;
use cw_storage_plus::Map;
use std::collections::HashMap;

use crate::state::{save_chain_config, ChainConfig as NewChainConfig};
use crate::shared::NumBits;

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

fn load_old_chain_config(storage: &dyn Storage, chain: &ChainNameRaw) -> Result<OldChainConfig, cosmwasm_std::StdError> {
    OLD_CHAIN_CONFIGS.load(storage, chain)
}

fn load_all_old_chain_configs(storage: &dyn Storage) -> Result<HashMap<ChainNameRaw, OldChainConfig>, cosmwasm_std::StdError> {
    OLD_CHAIN_CONFIGS
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .map(|res| res.map(|(chain, config)| (chain, config)))
        .collect::<Result<HashMap<_, _>, _>>()
}

#[cfg_attr(not(feature = "library"), entry_point)]
#[migrate_from_version("1.2")]
pub fn migrate(
    deps: DepsMut,
    _env: Env,
    msg: MigrateMsg,
) -> Result<Response, axelar_wasm_std::error::ContractError> {
    // Get all existing chains from old state format
    let existing_chains = load_all_old_chain_configs(deps.storage)
        .map_err(axelar_wasm_std::error::ContractError::from)?;
    
    // Create a set of chains specified in the migration message
    let migration_chains: HashSet<ChainNameRaw> = msg.chain_translation_configs
        .iter()
        .map(|config| config.chain.clone())
        .collect();
    
    // Check that all existing chains are specified in the migration
    for existing_chain in existing_chains.keys() {
        if !migration_chains.contains(existing_chain) {
            return Err(axelar_wasm_std::error::ContractError::from(
                cosmwasm_std::StdError::generic_err(format!("Chain '{}' exists in state but is not specified in migration", existing_chain))
            ));
        }
    }
    
    // Migrate each chain's config by loading old state and saving new state
    for chain_config in msg.chain_translation_configs {
        // Load the old chain config (without translation_contract)
        let old_chain_state = load_old_chain_config(deps.storage, &chain_config.chain)
            .map_err(|e| axelar_wasm_std::error::ContractError::from(
                cosmwasm_std::StdError::generic_err(format!("Failed to load old chain config for {}: {}", chain_config.chain, e))
            ))?;
        
        // Create new chain config with translation_contract added
        let new_chain_state = NewChainConfig {
            truncation: crate::state::TruncationConfig {
                max_uint_bits: old_chain_state.truncation.max_uint_bits,
                max_decimals_when_truncating: old_chain_state.truncation.max_decimals_when_truncating,
            },
            its_address: old_chain_state.its_address,
            frozen: old_chain_state.frozen,
            translation_contract: chain_config.translation_contract,
        };
        
        // Save the new chain config (this will overwrite the old format)
        save_chain_config(deps.storage, &chain_config.chain, &new_chain_state)
            .map_err(axelar_wasm_std::error::ContractError::from)?;
    }
    
    Ok(Response::new()
        .add_attribute("action", "migrate")
        .add_attribute("chains_updated", migration_chains.len().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{CONTRACT_NAME, CONTRACT_VERSION};
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{Addr, from_json};
    
    use crate::state::{save_config, load_chain_config, Config};
    use crate::shared::NumBits;

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
            axelarnet_gateway: Addr::unchecked("gateway"),
            operator: Addr::unchecked("operator"),
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
            its_address: Address::try_from("0x1234567890123456789012345678901234567890".to_string()).unwrap(),
            frozen: false,
        };

        let polygon_config = OldChainConfig {
            truncation: OldTruncationConfig {
                max_uint_bits: NumBits::try_from(256u32).unwrap(),
                max_decimals_when_truncating: 18,
            },
            its_address: Address::try_from("0x9876543210987654321098765432109876543210".to_string()).unwrap(),
            frozen: true, // Test with frozen chain
        };

        // Save in old format
        OLD_CHAIN_CONFIGS.save(deps.as_mut().storage, &ethereum_chain, &ethereum_config).unwrap();
        OLD_CHAIN_CONFIGS.save(deps.as_mut().storage, &polygon_chain, &polygon_config).unwrap();
    }

    #[test]
    fn test_migrate_success() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        setup_test_chains_old_format(&mut deps);

        let ethereum_translation = Address::try_from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()).unwrap();
        let polygon_translation = Address::try_from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()).unwrap();

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
        
        // Check response attributes
        assert_eq!(result.attributes.len(), 2);
        assert_eq!(result.attributes[0].key, "action");
        assert_eq!(result.attributes[0].value, "migrate");
        assert_eq!(result.attributes[1].key, "chains_updated");
        assert_eq!(result.attributes[1].value, "2");

        // Verify that translation contracts were added to the new format
        let ethereum_config = load_chain_config(deps.as_ref().storage, &ChainNameRaw::try_from("ethereum").unwrap()).unwrap();
        let polygon_config = load_chain_config(deps.as_ref().storage, &ChainNameRaw::try_from("polygon").unwrap()).unwrap();

        assert_eq!(ethereum_config.translation_contract, ethereum_translation);
        assert_eq!(polygon_config.translation_contract, polygon_translation);
        
        // Verify other fields were preserved
        assert_eq!(ethereum_config.its_address, Address::try_from("0x1234567890123456789012345678901234567890".to_string()).unwrap());
        assert_eq!(polygon_config.its_address, Address::try_from("0x9876543210987654321098765432109876543210".to_string()).unwrap());
        assert!(!ethereum_config.frozen);
        assert!(polygon_config.frozen); // Should preserve frozen state
        
        // Verify truncation config preserved
        assert_eq!(ethereum_config.truncation.max_uint_bits, NumBits::try_from(256u32).unwrap());
        assert_eq!(ethereum_config.truncation.max_decimals_when_truncating, 18);
        assert_eq!(polygon_config.truncation.max_uint_bits, NumBits::try_from(256u32).unwrap());
        assert_eq!(polygon_config.truncation.max_decimals_when_truncating, 18);
    }

    #[test]
    fn test_migrate_fails_when_chain_missing_from_message() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        setup_test_chains_old_format(&mut deps);

        // Only specify ethereum, missing polygon
        let msg = MigrateMsg {
            chain_translation_configs: vec![
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("ethereum").unwrap(),
                    translation_contract: Address::try_from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()).unwrap(),
                },
            ],
        };

        let result = migrate(deps.as_mut(), env, msg);
        
        // Should fail because polygon chain exists in state but is not in the migration message
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("polygon"));
        assert!(error_msg.contains("exists in state but is not specified in migration"));
    }

    #[test]
    fn test_migrate_fails_when_chain_not_in_state() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        setup_test_chains_old_format(&mut deps);

        // Include a chain that doesn't exist in state
        let msg = MigrateMsg {
            chain_translation_configs: vec![
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("ethereum").unwrap(),
                    translation_contract: Address::try_from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()).unwrap(),
                },
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("polygon").unwrap(),
                    translation_contract: Address::try_from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()).unwrap(),
                },
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("nonexistent").unwrap(),
                    translation_contract: Address::try_from("0xcccccccccccccccccccccccccccccccccccccccc".to_string()).unwrap(),
                },
            ],
        };

        let result = migrate(deps.as_mut(), env, msg);
        
        // Should fail because nonexistent chain is not in old state
        assert!(result.is_err());
        let error_msg = format!("{}", result.unwrap_err());
        assert!(error_msg.contains("Failed to load old chain config for nonexistent"));
    }

    #[test]
    fn test_migrate_empty_chains() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        // Set up contract version (normally done during instantiation)
        cw2::set_contract_version(&mut deps.storage, CONTRACT_NAME, CONTRACT_VERSION).unwrap();
        
        // Save config but no chains
        let config = Config {
            axelarnet_gateway: Addr::unchecked("gateway"),
            operator: Addr::unchecked("operator"),
        };
        save_config(deps.as_mut().storage, &config).unwrap();

        let msg = MigrateMsg {
            chain_translation_configs: vec![],
        };

        let result = migrate(deps.as_mut(), env, msg).unwrap();
        
        // Should succeed with empty chains
        assert_eq!(result.attributes[1].value, "0");
    }

    #[test]
    fn test_migrate_single_chain() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        // Set up contract version (normally done during instantiation)
        cw2::set_contract_version(&mut deps.storage, CONTRACT_NAME, CONTRACT_VERSION).unwrap();
        
        // Save config
        let config = Config {
            axelarnet_gateway: Addr::unchecked("gateway"),
            operator: Addr::unchecked("operator"),
        };
        save_config(deps.as_mut().storage, &config).unwrap();

        // Setup single chain in old format
        let avalanche_chain = ChainNameRaw::try_from("avalanche").unwrap();
        let avalanche_config = OldChainConfig {
            truncation: OldTruncationConfig {
                max_uint_bits: NumBits::try_from(128u32).unwrap(),
                max_decimals_when_truncating: 6,
            },
            its_address: Address::try_from("0xaabbccddaabbccddaabbccddaabbccddaabbccdd".to_string()).unwrap(),
            frozen: false,
        };
        OLD_CHAIN_CONFIGS.save(deps.as_mut().storage, &avalanche_chain, &avalanche_config).unwrap();

        let avalanche_translation = Address::try_from("0xdddddddddddddddddddddddddddddddddddddddd".to_string()).unwrap();

        let msg = MigrateMsg {
            chain_translation_configs: vec![
                ChainTranslationConfig {
                    chain: avalanche_chain.clone(),
                    translation_contract: avalanche_translation.clone(),
                },
            ],
        };

        let result = migrate(deps.as_mut(), env, msg).unwrap();
        
        // Check response
        assert_eq!(result.attributes[1].value, "1");

        // Verify migration
        let new_config = load_chain_config(deps.as_ref().storage, &avalanche_chain).unwrap();
        assert_eq!(new_config.translation_contract, avalanche_translation);
        assert_eq!(new_config.its_address, Address::try_from("0xaabbccddaabbccddaabbccddaabbccddaabbccdd".to_string()).unwrap());
        assert_eq!(new_config.truncation.max_uint_bits, NumBits::try_from(128u32).unwrap());
        assert_eq!(new_config.truncation.max_decimals_when_truncating, 6);
        assert!(!new_config.frozen);
    }

    #[test]
    fn test_migrate_preserves_different_truncation_configs() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        // Set up contract version (normally done during instantiation)
        cw2::set_contract_version(&mut deps.storage, CONTRACT_NAME, CONTRACT_VERSION).unwrap();
        
        // Save config
        let config = Config {
            axelarnet_gateway: Addr::unchecked("gateway"),
            operator: Addr::unchecked("operator"),
        };
        save_config(deps.as_mut().storage, &config).unwrap();

        // Setup chains with different truncation configs
        let chain1 = ChainNameRaw::try_from("chain1").unwrap();
        let chain2 = ChainNameRaw::try_from("chain2").unwrap();

        let config1 = OldChainConfig {
            truncation: OldTruncationConfig {
                max_uint_bits: NumBits::try_from(64u32).unwrap(),
                max_decimals_when_truncating: 8,
            },
            its_address: Address::try_from("0x1111111111111111111111111111111111111111".to_string()).unwrap(),
            frozen: false,
        };

        let config2 = OldChainConfig {
            truncation: OldTruncationConfig {
                max_uint_bits: NumBits::try_from(256u32).unwrap(),
                max_decimals_when_truncating: 18,
            },
            its_address: Address::try_from("0x2222222222222222222222222222222222222222".to_string()).unwrap(),
            frozen: true,
        };

        OLD_CHAIN_CONFIGS.save(deps.as_mut().storage, &chain1, &config1).unwrap();
        OLD_CHAIN_CONFIGS.save(deps.as_mut().storage, &chain2, &config2).unwrap();

        let msg = MigrateMsg {
            chain_translation_configs: vec![
                ChainTranslationConfig {
                    chain: chain1.clone(),
                    translation_contract: Address::try_from("0xaaaa".to_string()).unwrap(),
                },
                ChainTranslationConfig {
                    chain: chain2.clone(),
                    translation_contract: Address::try_from("0xbbbb".to_string()).unwrap(),
                },
            ],
        };

        let result = migrate(deps.as_mut(), env, msg).unwrap();
        assert_eq!(result.attributes[1].value, "2");

        // Verify different configs preserved
        let new_config1 = load_chain_config(deps.as_ref().storage, &chain1).unwrap();
        let new_config2 = load_chain_config(deps.as_ref().storage, &chain2).unwrap();

        assert_eq!(new_config1.truncation.max_uint_bits, NumBits::try_from(64u32).unwrap());
        assert_eq!(new_config1.truncation.max_decimals_when_truncating, 8);
        assert!(!new_config1.frozen);

        assert_eq!(new_config2.truncation.max_uint_bits, NumBits::try_from(256u32).unwrap());
        assert_eq!(new_config2.truncation.max_decimals_when_truncating, 18);
        assert!(new_config2.frozen);
    }

    #[test]
    fn test_migrate_msg_serialization() {
        // Test that MigrateMsg can be properly serialized/deserialized
        let msg = MigrateMsg {
            chain_translation_configs: vec![
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("ethereum").unwrap(),
                    translation_contract: Address::try_from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()).unwrap(),
                },
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("polygon").unwrap(),
                    translation_contract: Address::try_from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()).unwrap(),
                },
            ],
        };

        // Test JSON serialization
        let json = cosmwasm_std::to_json_string(&msg).unwrap();
        let deserialized: MigrateMsg = from_json(json).unwrap();
        
        assert_eq!(msg.chain_translation_configs.len(), deserialized.chain_translation_configs.len());
        assert_eq!(msg.chain_translation_configs[0].chain, deserialized.chain_translation_configs[0].chain);
        assert_eq!(msg.chain_translation_configs[0].translation_contract, deserialized.chain_translation_configs[0].translation_contract);
    }

    #[test]
    fn test_migrate_duplicate_chains_in_message() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        setup_test_chains_old_format(&mut deps);

        // Include duplicate chain in migration message
        let msg = MigrateMsg {
            chain_translation_configs: vec![
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("ethereum").unwrap(),
                    translation_contract: Address::try_from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()).unwrap(),
                },
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("ethereum").unwrap(), // Duplicate
                    translation_contract: Address::try_from("0xdddddddddddddddddddddddddddddddddddddddd".to_string()).unwrap(),
                },
                ChainTranslationConfig {
                    chain: ChainNameRaw::try_from("polygon").unwrap(),
                    translation_contract: Address::try_from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()).unwrap(),
                },
            ],
        };

        // Should succeed - the last translation contract for ethereum will be used
        let result = migrate(deps.as_mut(), env, msg).unwrap();
        assert_eq!(result.attributes[1].value, "2"); // Only 2 unique chains

        // Verify the last translation contract was used
        let ethereum_config = load_chain_config(deps.as_ref().storage, &ChainNameRaw::try_from("ethereum").unwrap()).unwrap();
        assert_eq!(ethereum_config.translation_contract, Address::try_from("0xdddddddddddddddddddddddddddddddddddddddd".to_string()).unwrap());
    }
}

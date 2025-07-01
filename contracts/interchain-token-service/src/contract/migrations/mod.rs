mod legacy_state;

use axelar_wasm_std::address::validate_cosmwasm_address;
use axelar_wasm_std::{migrate_from_version, IntoContractError};
use cosmwasm_schema::cw_serde;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{DepsMut, Env, Response};
use error_stack::ResultExt;
use router_api::Address;

use crate::state::{save_chain_config, ChainConfig as NewChainConfig};

#[cw_serde]
pub struct MigrateMsg {
    /// Translation contract address to use for all chains
    pub msg_translator: Address,
}

#[derive(thiserror::Error, Debug, IntoContractError)]
pub enum Error {
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
    let existing_chains = legacy_state::load_all_chain_configs(deps.storage)
        .change_context(Error::LoadOldChainConfigs)?;

    // Validate the translation contract address once
    let validated_translator =
        validate_cosmwasm_address(deps.api, &msg.msg_translator.to_string())?;

    for (chain, old_chain_state) in existing_chains {
        let new_chain_state = NewChainConfig {
            truncation: crate::state::TruncationConfig {
                max_uint_bits: old_chain_state.truncation.max_uint_bits,
                max_decimals_when_truncating: old_chain_state
                    .truncation
                    .max_decimals_when_truncating,
            },
            its_address: old_chain_state.its_address,
            frozen: old_chain_state.frozen,
            msg_translator: validated_translator.clone(),
        };

        save_chain_config(deps.storage, &chain, &new_chain_state)?;
    }

    Ok(Response::new())
}

#[cfg(test)]
mod tests {
    use assert_ok::assert_ok;
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
        let ethereum_chain = router_api::ChainNameRaw::try_from("ethereum").unwrap();
        let polygon_chain = router_api::ChainNameRaw::try_from("polygon").unwrap();

        let ethereum_config = legacy_state::ChainConfig {
            truncation: legacy_state::TruncationConfig {
                max_uint_bits: NumBits::try_from(256u32).unwrap(),
                max_decimals_when_truncating: 18,
            },
            its_address: Address::try_from(
                MockApi::default().addr_make("ethereum_its").to_string(),
            )
            .unwrap(),
            frozen: false,
        };

        let polygon_config = legacy_state::ChainConfig {
            truncation: legacy_state::TruncationConfig {
                max_uint_bits: NumBits::try_from(256u32).unwrap(),
                max_decimals_when_truncating: 18,
            },
            its_address: Address::try_from(MockApi::default().addr_make("polygon_its").to_string())
                .unwrap(),
            frozen: true, // Test with frozen chain
        };

        // Save in old format
        legacy_state::CHAIN_CONFIGS
            .save(deps.as_mut().storage, &ethereum_chain, &ethereum_config)
            .unwrap();
        legacy_state::CHAIN_CONFIGS
            .save(deps.as_mut().storage, &polygon_chain, &polygon_config)
            .unwrap();
    }

    #[test]
    fn test_migrate_success() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        setup_test_chains_old_format(&mut deps);

        let translation_contract = Address::try_from(
            MockApi::default()
                .addr_make("global_translation")
                .to_string(),
        )
        .unwrap();

        let msg = MigrateMsg {
            msg_translator: translation_contract.clone(),
        };

        migrate(deps.as_mut(), env, msg).unwrap();

        // Verify that the same translation contract was added to all chains
        let ethereum_config = load_chain_config(
            deps.as_ref().storage,
            &router_api::ChainNameRaw::try_from("ethereum").unwrap(),
        )
        .unwrap();
        let polygon_config = load_chain_config(
            deps.as_ref().storage,
            &router_api::ChainNameRaw::try_from("polygon").unwrap(),
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
            ethereum_config.msg_translator,
            MockApi::default().addr_make("global_translation")
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
            polygon_config.msg_translator,
            MockApi::default().addr_make("global_translation")
        );
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
        let ethereum_chain = router_api::ChainNameRaw::try_from("ethereum").unwrap();
        let ethereum_config = legacy_state::ChainConfig {
            truncation: legacy_state::TruncationConfig {
                max_uint_bits: NumBits::try_from(128u32).unwrap(),
                max_decimals_when_truncating: 6,
            },
            its_address: Address::try_from(
                MockApi::default().addr_make("ethereum_its").to_string(),
            )
            .unwrap(),
            frozen: false,
        };

        legacy_state::CHAIN_CONFIGS
            .save(deps.as_mut().storage, &ethereum_chain, &ethereum_config)
            .unwrap();

        let msg = MigrateMsg {
            msg_translator: Address::try_from(
                MockApi::default()
                    .addr_make("single_translation")
                    .to_string(),
            )
            .unwrap(),
        };

        assert_ok!(migrate(deps.as_mut(), env, msg));

        // Verify the migrated config
        let migrated_config = load_chain_config(
            deps.as_ref().storage,
            &router_api::ChainNameRaw::try_from("ethereum").unwrap(),
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
            migrated_config.msg_translator,
            MockApi::default().addr_make("single_translation")
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
        let ethereum_chain = router_api::ChainNameRaw::try_from("ethereum").unwrap();
        let polygon_chain = router_api::ChainNameRaw::try_from("polygon").unwrap();

        let ethereum_config = legacy_state::ChainConfig {
            truncation: legacy_state::TruncationConfig {
                max_uint_bits: NumBits::try_from(256u32).unwrap(),
                max_decimals_when_truncating: 18,
            },
            its_address: Address::try_from(
                MockApi::default().addr_make("ethereum_its").to_string(),
            )
            .unwrap(),
            frozen: false,
        };

        let polygon_config = legacy_state::ChainConfig {
            truncation: legacy_state::TruncationConfig {
                max_uint_bits: NumBits::try_from(128u32).unwrap(),
                max_decimals_when_truncating: 6,
            },
            its_address: Address::try_from(MockApi::default().addr_make("polygon_its").to_string())
                .unwrap(),
            frozen: true,
        };

        legacy_state::CHAIN_CONFIGS
            .save(deps.as_mut().storage, &ethereum_chain, &ethereum_config)
            .unwrap();
        legacy_state::CHAIN_CONFIGS
            .save(deps.as_mut().storage, &polygon_chain, &polygon_config)
            .unwrap();

        let msg = MigrateMsg {
            msg_translator: Address::try_from(
                MockApi::default()
                    .addr_make("shared_translation")
                    .to_string(),
            )
            .unwrap(),
        };

        assert_ok!(migrate(deps.as_mut(), env, msg));

        // Verify different truncation configs are preserved but same translation contract is used
        let ethereum_migrated = load_chain_config(
            deps.as_ref().storage,
            &router_api::ChainNameRaw::try_from("ethereum").unwrap(),
        )
        .unwrap();
        let polygon_migrated = load_chain_config(
            deps.as_ref().storage,
            &router_api::ChainNameRaw::try_from("polygon").unwrap(),
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

        // Both should have the same translation contract
        assert_eq!(
            ethereum_migrated.msg_translator,
            MockApi::default().addr_make("shared_translation")
        );
        assert_eq!(
            polygon_migrated.msg_translator,
            MockApi::default().addr_make("shared_translation")
        );
    }
}

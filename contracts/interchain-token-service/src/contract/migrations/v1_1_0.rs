use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, Order, Uint256, Uint512};
use cw_storage_plus::{Item, Map};
use itertools::Itertools;
use router_api::{Address, ChainNameRaw};

use super::MigrateMsg;
use crate::shared::NumBits;
use crate::state::{self, Config};

#[cw_serde]
pub struct OldConfig {
    pub axelarnet_gateway: Addr,
}

const OLD_CONFIG: Item<OldConfig> = Item::new("config");

#[cw_serde]
pub struct ChainConfig {
    pub truncation: TruncationConfig,
    pub its_address: Address,
    pub frozen: bool,
}

#[cw_serde]
pub struct TruncationConfig {
    pub max_uint: nonempty::Uint256, // The maximum number of bits used to represent unsigned integer values that is supported by the chain's token standard
    pub max_decimals_when_truncating: u8, // The maximum number of decimals that is preserved when deploying from a chain with a larger max unsigned integer
}

const OLD_CHAIN_CONFIGS: Map<&ChainNameRaw, ChainConfig> = Map::new("chain_configs");
const NEW_CHAIN_CONFIGS: Map<&ChainNameRaw, state::ChainConfig> = Map::new("chain_configs");

pub fn migrate(deps: DepsMut, msg: MigrateMsg) -> Result<(), ContractError> {
    let operator =
        axelar_wasm_std::address::validate_cosmwasm_address(deps.api, &msg.operator_address)?;
    let old_config = OLD_CONFIG.load(deps.storage)?;
    state::save_config(
        deps.storage,
        &Config {
            operator,
            axelarnet_gateway: old_config.axelarnet_gateway,
        },
    )?;
    let old_configs: Vec<_> = OLD_CHAIN_CONFIGS
        .range(deps.storage, None, None, Order::Ascending)
        .try_collect()?;

    let transformed_configs: Vec<(ChainNameRaw, state::ChainConfig)> = old_configs
        .into_iter()
        .map(|(chain_name, old_config)| {
            convert_max_uint_to_max_bits(old_config.truncation.max_uint).map(|max_uint_bits| {
                (
                    chain_name,
                    state::ChainConfig {
                        truncation: state::TruncationConfig {
                            max_decimals_when_truncating: old_config
                                .truncation
                                .max_decimals_when_truncating,
                            max_uint_bits,
                        },
                        its_address: old_config.its_address,
                        frozen: old_config.frozen,
                    },
                )
            })
        })
        .try_collect()?;

    for (chain, config) in transformed_configs {
        NEW_CHAIN_CONFIGS.save(deps.storage, &chain, &config)?;
    }

    Ok(())
}

fn convert_max_uint_to_max_bits(max_uint: nonempty::Uint256) -> Result<NumBits, ContractError> {
    let fixed_cases = [256, 128, 64, 32];
    for case in fixed_cases {
        // some chains were incorrectly registered with the max number of bits as the max uint
        if *max_uint == Uint256::from_u128(case as u128) {
            return NumBits::try_from(case).map_err(|err| err.into());
        }
    }
    // Need to add one to correctly get the number of bits. This will round down if the result is not a power of two
    #[allow(clippy::arithmetic_side_effects)] // can't possibly overflow
    NumBits::try_from((Uint512::from(*max_uint) + Uint512::one()).ilog2()).map_err(|err| err.into())
}

#[cfg(test)]
mod test {
    use assert_ok::assert_ok;
    use cosmwasm_std::testing::{mock_dependencies, MockApi};
    use cosmwasm_std::Uint256;
    use router_api::{Address, ChainNameRaw};

    use super::{migrate, ChainConfig, OLD_CHAIN_CONFIGS};
    use crate::contract::migrations::v1_1_0::{OldConfig, NEW_CHAIN_CONFIGS, OLD_CONFIG};
    use crate::contract::migrations::MigrateMsg;
    use crate::shared::NumBits;
    use crate::state;

    #[test]
    fn should_migrate_max_uints() {
        let mut deps = mock_dependencies();
        OLD_CONFIG
            .save(
                &mut deps.storage,
                &OldConfig {
                    axelarnet_gateway: MockApi::default().addr_make("axelarnet-gateway"),
                },
            )
            .unwrap();
        let old_configs = [
            (
                ChainNameRaw::try_from("ethereum").unwrap(),
                ChainConfig {
                    truncation: super::TruncationConfig {
                        max_uint: Uint256::MAX.try_into().unwrap(),
                        max_decimals_when_truncating: 18,
                    },
                    its_address: Address::try_from("0x00".to_string()).unwrap(),
                    frozen: false,
                },
            ),
            (
                ChainNameRaw::try_from("solana").unwrap(),
                ChainConfig {
                    truncation: super::TruncationConfig {
                        max_uint: Uint256::from_u128(256u128).try_into().unwrap(),
                        max_decimals_when_truncating: 18,
                    },
                    its_address: Address::try_from("0x00".to_string()).unwrap(),
                    frozen: false,
                },
            ),
        ];

        for (chain, config) in &old_configs {
            OLD_CHAIN_CONFIGS
                .save(&mut deps.storage, chain, config)
                .unwrap();
        }

        assert_ok!(migrate(
            deps.as_mut(),
            MigrateMsg {
                operator_address: MockApi::default().addr_make("operator").to_string()
            }
        ));

        for (chain, old_config) in old_configs {
            let new_config = NEW_CHAIN_CONFIGS.load(&deps.storage, &chain).unwrap();
            assert_eq!(new_config.its_address, old_config.its_address);
            assert_eq!(
                new_config.truncation.max_decimals_when_truncating,
                old_config.truncation.max_decimals_when_truncating
            );
            assert_eq!(new_config.frozen, old_config.frozen);
            assert_eq!(
                new_config.truncation.max_uint_bits,
                NumBits::try_from(256).unwrap()
            );
        }
    }

    #[test]
    fn should_set_operator() {
        let mut deps = mock_dependencies();
        OLD_CONFIG
            .save(
                &mut deps.storage,
                &OldConfig {
                    axelarnet_gateway: MockApi::default().addr_make("axelarnet-gateway"),
                },
            )
            .unwrap();

        let expected_operator = MockApi::default().addr_make("operator");
        assert_ok!(migrate(
            deps.as_mut(),
            MigrateMsg {
                operator_address: expected_operator.to_string()
            }
        ));

        let found_operator = state::load_config(&deps.storage).operator;
        assert_eq!(found_operator, expected_operator);
    }
}

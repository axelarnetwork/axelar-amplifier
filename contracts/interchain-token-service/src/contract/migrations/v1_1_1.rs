use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut, Order, Uint512};
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
    // Need to add one to correctly get the number of bits. This will round down if the result is not a power of two
    #[allow(clippy::arithmetic_side_effects)] // can't possibly overflow
    NumBits::try_from(Uint512::from(*max_uint).ilog2() + 1).map_err(|err| err.into())
}

#[cfg(test)]
mod test {
    use assert_ok::assert_ok;
    use cosmwasm_std::testing::{mock_dependencies, MockApi};
    use cosmwasm_std::Uint256;
    use router_api::{Address, ChainNameRaw};

    use super::{migrate, ChainConfig, OLD_CHAIN_CONFIGS};
    use crate::contract::migrations::v1_1_1::{
        convert_max_uint_to_max_bits, OldConfig, NEW_CHAIN_CONFIGS, OLD_CONFIG,
    };
    use crate::contract::migrations::MigrateMsg;
    use crate::shared::NumBits;
    use crate::state;

    #[test]
    fn convert_max_uint_to_max_bits_should_convert_correctly() {
        // standard max uints
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(u32::MAX).try_into().unwrap()).unwrap(),
            NumBits::try_from(32).unwrap()
        );
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(u64::MAX).try_into().unwrap()).unwrap(),
            NumBits::try_from(64).unwrap()
        );
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(u128::MAX).try_into().unwrap()).unwrap(),
            NumBits::try_from(128).unwrap()
        );
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::MAX.try_into().unwrap()).unwrap(),
            NumBits::try_from(256).unwrap()
        );

        // other powers of two
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(2u128.pow(127) - 1).try_into().unwrap())
                .unwrap(),
            NumBits::try_from(127).unwrap()
        );
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(2u128.pow(100) - 1).try_into().unwrap())
                .unwrap(),
            NumBits::try_from(100).unwrap()
        );

        // numbers that are not powers of two
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(u128::MAX - 10).try_into().unwrap())
                .unwrap(),
            NumBits::try_from(128).unwrap()
        );
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(u32::MAX - 10).try_into().unwrap()).unwrap(),
            NumBits::try_from(32).unwrap()
        );

        // very small numbers
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(32u32).try_into().unwrap()).unwrap(),
            NumBits::try_from(6).unwrap()
        );
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(64u32).try_into().unwrap()).unwrap(),
            NumBits::try_from(7).unwrap()
        );
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(127u32).try_into().unwrap()).unwrap(),
            NumBits::try_from(7).unwrap()
        );
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(128u32).try_into().unwrap()).unwrap(),
            NumBits::try_from(8).unwrap()
        );
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(255u32).try_into().unwrap()).unwrap(),
            NumBits::try_from(8).unwrap()
        );
        assert_eq!(
            convert_max_uint_to_max_bits(Uint256::from(256u32).try_into().unwrap()).unwrap(),
            NumBits::try_from(9).unwrap()
        );
    }

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
                ChainNameRaw::try_from("avalanche").unwrap(),
                ChainConfig {
                    truncation: super::TruncationConfig {
                        max_uint: Uint256::from_u128(u128::MAX).try_into().unwrap(),
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
                        max_uint: Uint256::from_u128(2u128.pow(127) - 1).try_into().unwrap(),
                        max_decimals_when_truncating: 18,
                    },
                    its_address: Address::try_from("0x00".to_string()).unwrap(),
                    frozen: false,
                },
            ),
            (
                ChainNameRaw::try_from("xrpl").unwrap(),
                ChainConfig {
                    truncation: super::TruncationConfig {
                        max_uint: Uint256::from(u64::MAX).try_into().unwrap(),
                        max_decimals_when_truncating: 18,
                    },
                    its_address: Address::try_from("0x00".to_string()).unwrap(),
                    frozen: false,
                },
            ),
            (
                ChainNameRaw::try_from("xrpl-evm").unwrap(),
                ChainConfig {
                    truncation: super::TruncationConfig {
                        max_uint: Uint256::from(u32::MAX).try_into().unwrap(),
                        max_decimals_when_truncating: 18,
                    },
                    its_address: Address::try_from("0x00".to_string()).unwrap(),
                    frozen: false,
                },
            ),
            (
                ChainNameRaw::try_from("polygon").unwrap(),
                ChainConfig {
                    truncation: super::TruncationConfig {
                        max_uint: Uint256::from(256u32).try_into().unwrap(),
                        max_decimals_when_truncating: 18,
                    },
                    its_address: Address::try_from("0x00".to_string()).unwrap(),
                    frozen: false,
                },
            ),
            (
                ChainNameRaw::try_from("stellar").unwrap(),
                ChainConfig {
                    truncation: super::TruncationConfig {
                        max_uint: Uint256::from(127u32).try_into().unwrap(),
                        max_decimals_when_truncating: 18,
                    },
                    its_address: Address::try_from("0x00".to_string()).unwrap(),
                    frozen: false,
                },
            ),
            (
                ChainNameRaw::try_from("stacks").unwrap(),
                ChainConfig {
                    truncation: super::TruncationConfig {
                        max_uint: Uint256::from(64u32).try_into().unwrap(),
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

        let expected_num_bits = [256, 128, 127, 64, 32, 9, 7, 7];
        for ((chain, old_config), expected_num_bits) in old_configs.iter().zip(expected_num_bits) {
            let new_config = NEW_CHAIN_CONFIGS.load(&deps.storage, &chain).unwrap();
            assert_eq!(new_config.its_address, old_config.its_address);
            assert_eq!(
                new_config.truncation.max_decimals_when_truncating,
                old_config.truncation.max_decimals_when_truncating
            );
            assert_eq!(new_config.frozen, old_config.frozen);
            assert_eq!(
                new_config.truncation.max_uint_bits,
                NumBits::try_from(expected_num_bits).unwrap()
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

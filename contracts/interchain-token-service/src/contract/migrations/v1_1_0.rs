use axelar_wasm_std::error::ContractError;
use axelar_wasm_std::nonempty;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Order, Storage, Uint256, Uint512};
use cw_storage_plus::Map;
use itertools::Itertools;
use router_api::{Address, ChainNameRaw};

use crate::shared::NumBits;
use crate::state;

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

pub fn migrate(storage: &mut dyn Storage) -> Result<(), ContractError> {
    let old_configs: Vec<_> = OLD_CHAIN_CONFIGS
        .range(storage, None, None, Order::Ascending)
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
        NEW_CHAIN_CONFIGS.save(storage, &chain, &config)?;
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
    NumBits::try_from((Uint512::from(*max_uint) + Uint512::one()).ilog2()).map_err(|err| err.into())
}

#[cfg(test)]
mod test {
    use assert_ok::assert_ok;
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::Uint256;
    use router_api::{Address, ChainNameRaw};

    use super::{migrate, ChainConfig, OLD_CHAIN_CONFIGS};
    use crate::contract::migrations::v1_1_0::NEW_CHAIN_CONFIGS;
    use crate::shared::NumBits;

    #[test]
    fn should_migrate_max_uints() {
        let mut deps = mock_dependencies();
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

        assert_ok!(migrate(&mut deps.storage));

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
}

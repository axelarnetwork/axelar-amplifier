use std::collections::HashMap;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::Storage;
use cw_storage_plus::Map;
use router_api::{Address, ChainNameRaw};

use crate::shared::NumBits;

#[cw_serde]
pub struct TruncationConfig {
    pub max_uint_bits: NumBits,
    pub max_decimals_when_truncating: u8,
}

#[cw_serde]
pub struct ChainConfig {
    pub truncation: TruncationConfig,
    pub its_address: Address,
    pub frozen: bool,
    // Note: no translation_contract field in old state
}

// Storage map for old chain configs
pub const CHAIN_CONFIGS: Map<&ChainNameRaw, ChainConfig> = Map::new("chain_configs");

pub fn load_all_chain_configs(
    storage: &dyn Storage,
) -> Result<HashMap<ChainNameRaw, ChainConfig>, cosmwasm_std::StdError> {
    CHAIN_CONFIGS
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .collect::<Result<HashMap<_, _>, _>>()
}

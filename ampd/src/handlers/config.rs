use std::fmt::Debug;
use std::time::Duration;

use router_api::ChainName;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_with::with_prefix;

use crate::types::TMAddress;
use crate::url::Url;

with_prefix!(chain "chain_");
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type")]
pub enum Config {
    MultisigSigner {
        cosmwasm_contract: TMAddress,
        chain_name: ChainName,
    },
}

macro_rules! ensure_unique_config {
    ($configs:expr, $config_type:path, $config_name:expr) => {
        match $configs
            .iter()
            .filter(|config| matches!(config, $config_type { .. }))
            .count()
        {
            count if count > 1 => Err(de::Error::custom(format!(
                "only one {} config is allowed",
                $config_name
            ))),
            _ => Ok(()),
        }
    };
}

pub fn deserialize_handler_configs<'de, D>(deserializer: D) -> Result<Vec<Config>, D::Error>
where
    D: Deserializer<'de>,
{
    let configs: Vec<Config> = Deserialize::deserialize(deserializer)?;

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use router_api::chain_name;
    use serde_json::to_value;

    use crate::handlers::config::{deserialize_handler_configs, Config};
    use crate::types::TMAddress;
    use crate::url::Url;
    use crate::PREFIX;
}

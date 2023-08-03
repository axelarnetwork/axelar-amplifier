use std::collections::HashSet;
use std::fmt::Display;

use enum_display_derive::Display;
use ethers::types::U64;
use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::types::TMAddress;
use crate::url::Url;

pub mod error;
pub mod finalizer;
pub mod json_rpc;
pub mod message_verifier;

#[derive(Debug, Deserialize, PartialEq, Hash, Eq, Clone, Display)]
pub enum ChainName {
    Ethereum,
    Other(String),
}

impl PartialEq<connection_router::types::ChainName> for ChainName {
    fn eq(&self, other: &connection_router::types::ChainName) -> bool {
        self.to_string().eq_ignore_ascii_case(&other.to_string())
    }
}

impl ChainName {
    pub fn finalizer<'a, C, H>(
        &'a self,
        rpc_client: &'a C,
        confirmation_height: H,
    ) -> Box<dyn finalizer::Finalizer + 'a>
    where
        C: json_rpc::EthereumClient + Send + Sync,
        H: Into<U64>,
    {
        match self {
            ChainName::Ethereum => Box::new(finalizer::EthereumFinalizer::new(rpc_client)),
            ChainName::Other(_) => Box::new(finalizer::PoWFinalizer::new(rpc_client, confirmation_height)),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EvmChainConfig {
    pub name: ChainName,
    pub rpc_url: Url,
    pub l1_chain_name: Option<ChainName>,
    pub voting_verifier: TMAddress,
}

pub fn deserialize_evm_chain_configs<'de, D>(deserializer: D) -> core::result::Result<Vec<EvmChainConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    let evm_configs: Vec<EvmChainConfig> = Deserialize::deserialize(deserializer)?;

    // validate name being unique
    let chain_names: HashSet<&ChainName> = evm_configs.iter().map(|evm_config| &evm_config.name).collect();
    if evm_configs.len() != chain_names.len() {
        return Err(de::Error::custom("the evm_chain_configs must be unique by name"));
    }

    for config in &evm_configs {
        match &config.l1_chain_name {
            None => continue,
            Some(l1_chain_name) => {
                if !chain_names.contains(&l1_chain_name) {
                    return Err(de::Error::custom(
                        "l1_chain_name must be one of the evm_chain_configs if set",
                    ));
                }

                if *l1_chain_name == config.name {
                    return Err(de::Error::custom("l1_chain_name must not equal to name"));
                }
            }
        }
    }

    Ok(evm_configs)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::evm::ChainName;

    #[test]
    fn chain_name_partial_eq() {
        let chain_name = ChainName::Ethereum;

        assert!(chain_name == connection_router::types::ChainName::from_str("Ethereum").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("ETHEREUM").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("ethereum").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("ethEReum").unwrap());
        assert!(chain_name != connection_router::types::ChainName::from_str("Ethereum-1").unwrap());

        let chain_name = ChainName::Other("avalanche".into());

        assert!(chain_name == connection_router::types::ChainName::from_str("Avalanche").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("AVALANCHE").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("avalanche").unwrap());
        assert!(chain_name == connection_router::types::ChainName::from_str("avaLAnche").unwrap());
        assert!(chain_name != connection_router::types::ChainName::from_str("Avalanche-2").unwrap());
    }
}

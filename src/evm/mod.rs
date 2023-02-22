use crate::event_processor::EventHandler;
use crate::evm::finalizer::Finalizer;
use crate::handlers::evm_confirm_gateway_tx;
use crate::url::Url;
use enum_display_derive::Display;
use error_stack::{Result, ResultExt};
use serde::de::{self, Deserializer};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt::Display;

pub mod error;
pub mod finalizer;
pub mod json_rpc;

#[derive(Debug, Deserialize, PartialEq, Hash, Eq, Copy, Clone, Display)]
pub enum ChainName {
    Ethereum,
}

impl ChainName {
    pub fn matches<C>(&self, another: C) -> bool
    where
        C: Into<String>,
    {
        let name = self.to_string();
        let another = another.into();

        another.to_lowercase() == name.to_lowercase()
    }
}

#[derive(Debug, Deserialize)]
pub struct EvmChainConfig {
    pub name: ChainName,
    pub rpc_url: Url,
    pub l1_chain_name: Option<ChainName>,
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
        match config.l1_chain_name {
            None => continue,
            Some(l1_chain_name) => {
                if !chain_names.contains(&l1_chain_name) {
                    return Err(de::Error::custom(
                        "l1_chain_name must be one of the evm_chain_configs if set",
                    ));
                }

                if l1_chain_name == config.name {
                    return Err(de::Error::custom("l1_chain_name must not equal to name"));
                }
            }
        }
    }

    Ok(evm_configs)
}

async fn new_finalizer(
    evm_client_repo: &mut json_rpc::EVMClientRepo,
    config: &EvmChainConfig,
) -> Result<impl finalizer::Finalizer, error::Error> {
    let rpc_client = evm_client_repo
        .client(config.rpc_url.clone())
        .change_context(error::Error::JSONRPCError)?;
    let finalizer = match config.name {
        ChainName::Ethereum => finalizer::PoWFinalizer::new(rpc_client, 20),
    };
    let _ = finalizer.latest_finalized_block_height().await?;

    Ok(finalizer)
}

pub async fn confirm_gateway_tx_handler(
    evm_client_repo: &mut json_rpc::EVMClientRepo,
    config: &EvmChainConfig,
) -> Result<impl EventHandler, error::Error> {
    Ok(evm_confirm_gateway_tx::Handler::new(
        config.name,
        new_finalizer(evm_client_repo, config).await?,
        evm_client_repo
            .client(config.rpc_url.clone())
            .change_context(error::Error::JSONRPCError)?,
    ))
}

#[cfg(test)]
mod tests {
    use crate::evm::ChainName;

    #[test]
    fn chain_name_matches() {
        let chain_name = ChainName::Ethereum;

        assert!(chain_name.matches("Ethereum"));
        assert!(chain_name.matches("ETHEREUM"));
        assert!(chain_name.matches("ethereum"));
        assert!(chain_name.matches("ethEReum"));
    }
}

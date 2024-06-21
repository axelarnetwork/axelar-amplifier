use std::time::Duration;

use itertools::Itertools;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_with::with_prefix;

use crate::evm::finalizer::Finalization;
use crate::types::TMAddress;
use crate::url::Url;
use router_api::ChainName;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Chain {
    pub name: ChainName,
    pub rpc_url: Url,
    #[serde(default)]
    pub finalization: Finalization,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct GenericChain {
    pub name: ChainName,
    pub rpc_url: Url,
}

with_prefix!(chain "chain_");
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type")]
pub enum Config {
    EvmMsgVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(flatten, with = "chain")]
        chain: Chain,
        rpc_timeout: Option<Duration>,
    },
    EvmVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(flatten, with = "chain")]
        chain: Chain,
        rpc_timeout: Option<Duration>,
    },
    MultisigSigner {
        cosmwasm_contract: TMAddress,
    },
    SuiMsgVerifier {
        cosmwasm_contract: TMAddress,
        rpc_url: Url,
        rpc_timeout: Option<Duration>,
    },
    SuiVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        rpc_url: Url,
        rpc_timeout: Option<Duration>,
    },
    SolanaMsgVerifier {
        cosmwasm_contract: TMAddress,
        rpc_url: Url,
        max_tx_cache_entries: usize,
        #[serde(flatten, with = "chain")]
        chain: GenericChain,
    },
    SolanaWorkerSetVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(flatten, with = "chain")]
        chain: GenericChain,
    },
}

fn validate_multisig_signer_config<'de, D>(configs: &[Config]) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    match configs
        .iter()
        .filter(|config| matches!(config, Config::MultisigSigner { .. }))
        .count()
    {
        count if count > 1 => Err(de::Error::custom(
            "only one multisig signer config is allowed",
        )),
        _ => Ok(()),
    }
}
fn validate_evm_verifier_set_verifier_configs<'de, D>(configs: &[Config]) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    if !configs
        .iter()
        .filter_map(|config| match config {
            Config::EvmVerifierSetVerifier {
                chain: Chain { name, .. },
                ..
            } => Some(name),
            _ => None,
        })
        .all_unique()
    {
        return Err(de::Error::custom(
            "the chain name EVM verifier set verifier configs must be unique",
        ));
    }

    Ok(())
}

fn validate_evm_msg_verifier_configs<'de, D>(configs: &[Config]) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    if !configs
        .iter()
        .filter_map(|config| match config {
            Config::EvmMsgVerifier {
                chain: Chain { name, .. },
                ..
            } => Some(name),
            _ => None,
        })
        .all_unique()
    {
        return Err(de::Error::custom(
            "the chain name EVM msg verifier configs must be unique",
        ));
    }

    Ok(())
}

fn validate_sui_msg_verifier_config<'de, D>(configs: &[Config]) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    match configs
        .iter()
        .filter(|config| matches!(config, Config::SuiMsgVerifier { .. }))
        .count()
    {
        count if count > 1 => Err(de::Error::custom(
            "only one Sui msg verifier config is allowed",
        )),
        _ => Ok(()),
    }
}

fn validate_sui_verifier_set_verifier_config<'de, D>(configs: &[Config]) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    match configs
        .iter()
        .filter(|config| matches!(config, Config::SuiVerifierSetVerifier { .. }))
        .count()
    {
        count if count > 1 => Err(de::Error::custom(
            "only one Sui worker set verifier config is allowed",
        )),
        _ => Ok(()),
    }
}

fn validate_solana_msg_verifier_config<'de, D>(configs: &[Config]) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    if !configs
        .iter()
        .filter_map(|config| match config {
            Config::SolanaMsgVerifier {
                chain: GenericChain { name, .. },
                ..
            } => Some(name),
            _ => None,
        })
        .all_unique()
    {
        return Err(de::Error::custom(
            "the chain name Solana msg verifier configs must be unique",
        ));
    }

    match configs
        .iter()
        .filter(|config| matches!(config, Config::SolanaMsgVerifier { .. }))
        .count()
    {
        count if count > 1 => Err(de::Error::custom(
            "only one Solana msg verifier config is allowed",
        )),
        _ => Ok(()),
    }
}

fn validate_solana_worker_set_verifier_configs<'de, D>(configs: &[Config]) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    if !configs
        .iter()
        .filter_map(|config| match config {
            Config::SolanaWorkerSetVerifier {
                chain: GenericChain { name, .. },
                ..
            } => Some(name),
            _ => None,
        })
        .all_unique()
    {
        return Err(de::Error::custom(
            "the chain name Solana worker set verifier configs must be unique",
        ));
    }

    Ok(())
}

pub fn deserialize_handler_configs<'de, D>(deserializer: D) -> Result<Vec<Config>, D::Error>
where
    D: Deserializer<'de>,
{
    let configs: Vec<Config> = Deserialize::deserialize(deserializer)?;

    validate_evm_msg_verifier_configs::<D>(&configs)?;
    validate_evm_verifier_set_verifier_configs::<D>(&configs)?;
    validate_multisig_signer_config::<D>(&configs)?;
    validate_sui_msg_verifier_config::<D>(&configs)?;
    validate_sui_verifier_set_verifier_config::<D>(&configs)?;
    validate_solana_msg_verifier_config::<D>(&configs)?;
    validate_solana_worker_set_verifier_configs::<D>(&configs)?;

    Ok(configs)
}

#[cfg(test)]
mod tests {

    use crate::{evm::finalizer::Finalization, handlers::config::Chain};

    #[test]
    fn finalizer_should_default_to_ethereum() {
        let chain_config_toml = "
        name = 'polygon'
        rpc_url = 'http://127.0.0.1/'
        ";

        let chain_config: Chain = toml::from_str(chain_config_toml).unwrap();
        assert_eq!(chain_config.finalization, Finalization::RPCFinalizedBlock);
    }
}

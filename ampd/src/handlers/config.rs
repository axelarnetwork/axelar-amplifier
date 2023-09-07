use itertools::Itertools;
use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::evm::ChainName;
use crate::types::TMAddress;
use crate::url::Url;

#[derive(Debug, Deserialize)]
pub struct Chain {
    pub name: ChainName,
    pub rpc_url: Url,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum Config {
    EvmMsgVerifier {
        chain: Chain,
        cosmwasm_contract: TMAddress,
    },
    MultisigSigner {
        cosmwasm_contract: TMAddress,
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

pub fn deserialize_handler_configs<'de, D>(
    deserializer: D,
) -> core::result::Result<Vec<Config>, D::Error>
where
    D: Deserializer<'de>,
{
    let configs: Vec<Config> = Deserialize::deserialize(deserializer)?;

    validate_evm_msg_verifier_configs::<D>(&configs)?;
    validate_multisig_signer_config::<D>(&configs)?;

    Ok(configs)
}

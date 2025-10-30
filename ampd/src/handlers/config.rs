use std::fmt::Debug;
use std::time::Duration;

use itertools::Itertools;
use router_api::ChainName;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_with::with_prefix;

use crate::evm::finalizer::Finalization;
use crate::types::TMAddress;
use crate::url::Url;

#[derive(Clone, Deserialize, Serialize, PartialEq, Debug)]
pub struct Chain {
    pub name: ChainName,
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    pub rpc_url: Url,
    #[serde(default)]
    pub finalization: Finalization,
}

with_prefix!(chain "chain_");
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type")]
pub enum Config {
    EvmMsgVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(flatten, with = "chain")]
        chain: Chain,
        rpc_timeout: Option<Duration>,
    },
    EvmEventVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(flatten, with = "chain")]
        chain: Chain,
        rpc_timeout: Option<Duration>,
        confirmation_height: Option<u64>,
    },
    EvmVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(flatten, with = "chain")]
        chain: Chain,
        rpc_timeout: Option<Duration>,
    },
    MultisigSigner {
        cosmwasm_contract: TMAddress,
        chain_name: ChainName,
    },
    SuiMsgVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
        rpc_timeout: Option<Duration>,
    },
    SuiVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
        rpc_timeout: Option<Duration>,
    },
    XRPLMsgVerifier {
        cosmwasm_contract: TMAddress,
        chain_name: ChainName,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        chain_rpc_url: Url,
        rpc_timeout: Option<Duration>,
    },
    XRPLMultisigSigner {
        cosmwasm_contract: TMAddress,
        chain_name: ChainName,
    },
    MvxMsgVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        proxy_url: Url,
    },
    MvxVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        proxy_url: Url,
    },
    StellarMsgVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
    },
    StellarVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
    },
    StarknetMsgVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
    },
    StarknetVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
    },
    SolanaMsgVerifier {
        chain_name: ChainName,
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
        gateway_address: String,
        rpc_timeout: Option<Duration>,
    },
    SolanaVerifierSetVerifier {
        chain_name: ChainName,
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
        gateway_address: String,
        rpc_timeout: Option<Duration>,
    },
    StacksMsgVerifier {
        chain_name: ChainName,
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_non_sensitive")]
        rpc_url: Url,
        rpc_timeout: Option<Duration>,
    },
    StacksVerifierSetVerifier {
        chain_name: ChainName,
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_non_sensitive")]
        rpc_url: Url,
        rpc_timeout: Option<Duration>,
    },
}

fn validate_starknet_msg_verifier_config<'de, D>(configs: &[Config]) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    match configs
        .iter()
        .filter(|config| matches!(config, Config::StarknetMsgVerifier { .. }))
        .count()
    {
        count if count > 1 => Err(de::Error::custom(
            "only one Starknet msg verifier config is allowed",
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

fn validate_evm_event_verifier_configs<'de, D>(configs: &[Config]) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    if !configs
        .iter()
        .filter_map(|config| match config {
            Config::EvmEventVerifier {
                chain: Chain { name, .. },
                ..
            } => Some(name),
            _ => None,
        })
        .all_unique()
    {
        return Err(de::Error::custom(
            "the chain name EVM event verifier configs must be unique",
        ));
    }

    Ok(())
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

    validate_starknet_msg_verifier_config::<D>(&configs)?;
    validate_evm_msg_verifier_configs::<D>(&configs)?;
    validate_evm_event_verifier_configs::<D>(&configs)?;
    validate_evm_verifier_set_verifier_configs::<D>(&configs)?;

    ensure_unique_config!(&configs, Config::XRPLMsgVerifier, "XRPL message verifier")?;
    ensure_unique_config!(&configs, Config::SuiMsgVerifier, "Sui message verifier")?;
    ensure_unique_config!(
        &configs,
        Config::SuiVerifierSetVerifier,
        "Sui verifier set verifier"
    )?;
    ensure_unique_config!(&configs, Config::MvxMsgVerifier, "Mvx message verifier")?;
    ensure_unique_config!(
        &configs,
        Config::MvxVerifierSetVerifier,
        "Mvx verifier set verifier"
    )?;
    ensure_unique_config!(
        &configs,
        Config::StellarMsgVerifier,
        "Stellar message verifier"
    )?;
    ensure_unique_config!(
        &configs,
        Config::StellarVerifierSetVerifier,
        "Stellar verifier set verifier"
    )?;
    ensure_unique_config!(
        &configs,
        Config::SolanaMsgVerifier,
        "Solana message verifier"
    )?;
    ensure_unique_config!(
        &configs,
        Config::SolanaVerifierSetVerifier,
        "Solana verifier set verifier"
    )?;
    ensure_unique_config!(
        &configs,
        Config::StacksMsgVerifier,
        "Stacks message verifier"
    )?;
    ensure_unique_config!(
        &configs,
        Config::StacksVerifierSetVerifier,
        "Stacks verifier set verifier"
    )?;

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use router_api::chain_name;
    use serde_json::to_value;

    use crate::evm::finalizer::Finalization;
    use crate::handlers::config::{deserialize_handler_configs, Chain, Config};
    use crate::types::debug::REDACTED_VALUE;
    use crate::types::TMAddress;
    use crate::url::Url;
    use crate::PREFIX;

    const SOLANA: &str = "solana";
    const STACKS: &str = "stacks";

    #[test]
    fn finalizer_should_default_to_ethereum() {
        let chain_config_toml = "
        name = 'polygon'
        rpc_url = 'http://127.0.0.1/'
        ";

        let chain_config: Chain = toml::from_str(chain_config_toml).unwrap();
        assert_eq!(chain_config.finalization, Finalization::RPCFinalizedBlock);
    }

    #[test]
    fn unique_config_validation() {
        let configs = vec![
            Config::SuiMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
                rpc_timeout: None,
            },
            Config::SuiMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
                rpc_timeout: None,
            },
        ];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Sui message verifier config is allowed")
            )
        );

        let configs = vec![
            Config::SuiVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
                rpc_timeout: None,
            },
            Config::SuiVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
                rpc_timeout: None,
            },
        ];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Sui verifier set verifier config is allowed")
            )
        );

        let configs = vec![
            Config::MvxMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                proxy_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
            },
            Config::MvxMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                proxy_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
            },
        ];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Mvx message verifier config is allowed")
            )
        );

        let configs = vec![
            Config::MvxVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                proxy_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
            },
            Config::MvxVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                proxy_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
            },
        ];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Mvx verifier set verifier config is allowed")
            )
        );

        let configs = vec![
            Config::StellarMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
            },
            Config::StellarMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
            },
        ];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Stellar message verifier config is allowed")
            )
        );

        let configs = vec![
            Config::StellarVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
            },
            Config::StellarVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: Url::new_non_sensitive("http://localhost:7545/").unwrap(),
            },
        ];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Stellar verifier set verifier config is allowed")
            )
        );

        let sample_config = Config::SolanaMsgVerifier {
            chain_name: chain_name!(SOLANA),
            cosmwasm_contract: TMAddress::random(PREFIX),
            rpc_url: Url::new_non_sensitive("http://localhost:8080/").unwrap(),
            rpc_timeout: None,
            gateway_address: "11111111111111111111111111111112".to_string(),
        };

        let configs = vec![sample_config.clone(), sample_config];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Solana message verifier config is allowed")
            )
        );

        let sample_config = Config::SolanaVerifierSetVerifier {
            chain_name: chain_name!(SOLANA),
            cosmwasm_contract: TMAddress::random(PREFIX),
            rpc_url: Url::new_non_sensitive("http://localhost:8080/").unwrap(),
            rpc_timeout: None,
            gateway_address: "11111111111111111111111111111112".to_string(),
        };

        let configs = vec![sample_config.clone(), sample_config];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Solana verifier set verifier config is allowed")
            )
        );

        let sample_config = Config::StacksMsgVerifier {
            chain_name: chain_name!(STACKS),
            cosmwasm_contract: TMAddress::random(PREFIX),
            rpc_url: Url::new_non_sensitive("http://localhost:8080/").unwrap(),
            rpc_timeout: None,
        };

        let configs = vec![sample_config.clone(), sample_config];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Stacks message verifier config is allowed")
            )
        );

        let sample_config = Config::StacksVerifierSetVerifier {
            chain_name: chain_name!(STACKS),
            cosmwasm_contract: TMAddress::random(PREFIX),
            rpc_url: Url::new_non_sensitive("http://localhost:8080/").unwrap(),
            rpc_timeout: None,
        };

        let configs = vec![sample_config.clone(), sample_config];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Stacks verifier set verifier config is allowed")
            )
        );
    }
    #[test]
    fn test_chain_struct_debug_redacts_url() {
        let chain = Chain {
            name: chain_name!("ethereum"),
            rpc_url: Url::new_sensitive("http://localhost:7545/API_KEY").unwrap(),
            finalization: Finalization::RPCFinalizedBlock,
        };
        let debug_output = format!("{:?}", chain);
        assert!(debug_output.contains("ethereum"));
        assert!(debug_output.contains(REDACTED_VALUE));
        assert!(!debug_output.contains("API_KEY"));
        assert!(debug_output.contains("RPCFinalizedBlock"));
    }
}

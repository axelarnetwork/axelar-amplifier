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

#[derive(Clone, Debug)]
pub struct HandlerInfo {
    pub chain_name: String,
    pub verifier_id: String,
    pub cast_votes: bool,
    pub label: String,
}

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
        rpc_timeout: Option<Duration>,
    },
    SolanaVerifierSetVerifier {
        chain_name: ChainName,
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
        rpc_timeout: Option<Duration>,
    },
}

impl Config {
    pub fn handler_info(&self) -> HandlerInfo {
        match self {
            Config::EvmMsgVerifier {
                chain,
                cosmwasm_contract,
                ..
            } => HandlerInfo {
                chain_name: chain.name.to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: format!("{}-msg-verifier", chain.name),
            },

            Config::EvmVerifierSetVerifier {
                chain,
                cosmwasm_contract,
                ..
            } => HandlerInfo {
                chain_name: chain.name.to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: format!("{}-verifier-set-verifier", chain.name),
            },

            Config::MultisigSigner {
                chain_name,
                cosmwasm_contract,
                ..
            } => HandlerInfo {
                chain_name: chain_name.to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: false,
                label: format!("{}-multisig-signer", chain_name),
            },

            Config::SuiMsgVerifier {
                cosmwasm_contract, ..
            } => HandlerInfo {
                chain_name: "sui".to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: "sui-msg-verifier".to_string(),
            },

            Config::SuiVerifierSetVerifier {
                cosmwasm_contract, ..
            } => HandlerInfo {
                chain_name: "sui".to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: "sui-verifier-set-verifier".to_string(),
            },

            Config::XRPLMsgVerifier {
                chain_name,
                cosmwasm_contract,
                ..
            } => HandlerInfo {
                chain_name: chain_name.to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: format!("{}-msg-verifier", chain_name),
            },

            Config::XRPLMultisigSigner {
                chain_name,
                cosmwasm_contract,
                ..
            } => HandlerInfo {
                chain_name: chain_name.to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: false,
                label: format!("{}-multisig-signer", chain_name),
            },

            Config::MvxMsgVerifier {
                cosmwasm_contract, ..
            } => HandlerInfo {
                chain_name: "multiversx".to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: "mvx-msg-verifier".to_string(),
            },

            Config::MvxVerifierSetVerifier {
                cosmwasm_contract, ..
            } => HandlerInfo {
                chain_name: "multiversx".to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: "mvx-verifier-set-verifier".to_string(),
            },

            Config::StellarMsgVerifier {
                cosmwasm_contract, ..
            } => HandlerInfo {
                chain_name: "stellar".to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: "stellar-msg-verifier".to_string(),
            },

            Config::StellarVerifierSetVerifier {
                cosmwasm_contract, ..
            } => HandlerInfo {
                chain_name: "stellar".to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: "stellar-verifier-set-verifier".to_string(),
            },

            Config::StarknetMsgVerifier {
                cosmwasm_contract, ..
            } => HandlerInfo {
                chain_name: "starknet".to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: "starknet-msg-verifier".to_string(),
            },

            Config::StarknetVerifierSetVerifier {
                cosmwasm_contract, ..
            } => HandlerInfo {
                chain_name: "starknet".to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: "starknet-verifier-set-verifier".to_string(),
            },

            Config::SolanaMsgVerifier {
                chain_name,
                cosmwasm_contract,
                ..
            } => HandlerInfo {
                chain_name: chain_name.to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: "solana-msg-verifier".to_string(),
            },

            Config::SolanaVerifierSetVerifier {
                chain_name,
                cosmwasm_contract,
                ..
            } => HandlerInfo {
                chain_name: chain_name.to_string(),
                verifier_id: cosmwasm_contract.to_string(),
                cast_votes: true,
                label: "solana-verifier-set-verifier".to_string(),
            },
        }
    }
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

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use router_api::ChainName;
    use serde_json::to_value;

    use crate::evm::finalizer::Finalization;
    use crate::handlers::config::{deserialize_handler_configs, Chain, Config, HandlerInfo};
    use crate::types::debug::REDACTED_VALUE;
    use crate::types::TMAddress;
    use crate::url::Url;
    use crate::PREFIX;

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
            chain_name: ChainName::from_str("solana").unwrap(),
            cosmwasm_contract: TMAddress::random(PREFIX),
            rpc_url: Url::new_non_sensitive("http://localhost:8080/").unwrap(),
            rpc_timeout: None,
        };

        let configs = vec![sample_config.clone(), sample_config];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Solana message verifier config is allowed")
            )
        );

        let sample_config = Config::SolanaVerifierSetVerifier {
            chain_name: ChainName::from_str("solana").unwrap(),
            cosmwasm_contract: TMAddress::random(PREFIX),
            rpc_url: Url::new_non_sensitive("http://localhost:8080/").unwrap(),
            rpc_timeout: None,
        };

        let configs = vec![sample_config.clone(), sample_config];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Solana verifier set verifier config is allowed")
            )
        );
    }
    #[test]
    fn test_chain_struct_debug_redacts_url() {
        let chain = Chain {
            name: ChainName::from_str("ethereum").unwrap(),
            rpc_url: Url::new_sensitive("http://localhost:7545/API_KEY").unwrap(),
            finalization: Finalization::RPCFinalizedBlock,
        };
        let debug_output = format!("{:?}", chain);
        assert!(debug_output.contains("ethereum"));
        assert!(debug_output.contains(REDACTED_VALUE));
        assert!(!debug_output.contains("API_KEY"));
        assert!(debug_output.contains("RPCFinalizedBlock"));
    }

    #[test]
    fn evm_handlers_provide_correct_info() {
        let evm_contract = TMAddress::random(PREFIX);
        let evm_msg_config = Config::EvmMsgVerifier {
            cosmwasm_contract: evm_contract.clone(),
            chain: Chain {
                name: ChainName::from_str("ethereum").unwrap(),
                rpc_url: Url::new_non_sensitive("http://localhost:8545").unwrap(),
                finalization: Finalization::RPCFinalizedBlock,
            },
            rpc_timeout: None,
        };

        validate_handler_info(
            evm_msg_config.handler_info(),
            "ethereum".to_string(),
            evm_contract.to_string(),
            true,
            "ethereum-msg-verifier".to_string(),
        );

        let evm_verifier_set_contract = TMAddress::random(PREFIX);
        let evm_verifier_set_config = Config::EvmVerifierSetVerifier {
            cosmwasm_contract: evm_verifier_set_contract.clone(),
            chain: Chain {
                name: ChainName::from_str("polygon").unwrap(),
                rpc_url: Url::new_non_sensitive("http://localhost:8545").unwrap(),
                finalization: Finalization::RPCFinalizedBlock,
            },
            rpc_timeout: None,
        };

        validate_handler_info(
            evm_verifier_set_config.handler_info(),
            "polygon".to_string(),
            evm_verifier_set_contract.to_string(),
            true,
            "polygon-verifier-set-verifier".to_string(),
        );

        let multisig_contract = TMAddress::random(PREFIX);
        let multisig_config = Config::MultisigSigner {
            cosmwasm_contract: multisig_contract.clone(),
            chain_name: ChainName::from_str("ethereum").unwrap(),
        };

        validate_handler_info(
            multisig_config.handler_info(),
            "ethereum".to_string(),
            multisig_contract.to_string(),
            false,
            "ethereum-multisig-signer".to_string(),
        );
    }

    #[test]
    fn sui_handlers_provide_correct_info() {
        let sui_contract = TMAddress::random(PREFIX);
        let sui_msg_config = Config::SuiMsgVerifier {
            cosmwasm_contract: sui_contract.clone(),
            rpc_url: Url::new_non_sensitive("http://localhost:9000").unwrap(),
            rpc_timeout: None,
        };

        validate_handler_info(
            sui_msg_config.handler_info(),
            "sui".to_string(),
            sui_contract.to_string(),
            true,
            "sui-msg-verifier".to_string(),
        );

        let sui_verifier_set_contract = TMAddress::random(PREFIX);
        let sui_verifier_set_config = Config::SuiVerifierSetVerifier {
            cosmwasm_contract: sui_verifier_set_contract.clone(),
            rpc_url: Url::new_non_sensitive("http://localhost:9000").unwrap(),
            rpc_timeout: None,
        };

        validate_handler_info(
            sui_verifier_set_config.handler_info(),
            "sui".to_string(),
            sui_verifier_set_contract.to_string(),
            true,
            "sui-verifier-set-verifier".to_string(),
        );
    }

    #[test]
    fn xrpl_handlers_provide_correct_info() {
        let xrpl_contract = TMAddress::random(PREFIX);
        let xrpl_msg_config = Config::XRPLMsgVerifier {
            cosmwasm_contract: xrpl_contract.clone(),
            chain_name: ChainName::from_str("xrpl").unwrap(),
            chain_rpc_url: Url::new_non_sensitive("http://localhost:6006").unwrap(),
            rpc_timeout: None,
        };

        validate_handler_info(
            xrpl_msg_config.handler_info(),
            "xrpl".to_string(),
            xrpl_contract.to_string(),
            true,
            "xrpl-msg-verifier".to_string(),
        );

        let xrpl_multisig_contract = TMAddress::random(PREFIX);
        let xrpl_multisig_config = Config::XRPLMultisigSigner {
            cosmwasm_contract: xrpl_multisig_contract.clone(),
            chain_name: ChainName::from_str("xrpl").unwrap(),
        };

        validate_handler_info(
            xrpl_multisig_config.handler_info(),
            "xrpl".to_string(),
            xrpl_multisig_contract.to_string(),
            false,
            "xrpl-multisig-signer".to_string(),
        );
    }

    #[test]
    fn mvx_handlers_provide_correct_info() {
        let mvx_contract = TMAddress::random(PREFIX);
        let mvx_msg_config = Config::MvxMsgVerifier {
            cosmwasm_contract: mvx_contract.clone(),
            proxy_url: Url::new_non_sensitive("http://localhost:7950").unwrap(),
        };

        validate_handler_info(
            mvx_msg_config.handler_info(),
            "multiversx".to_string(),
            mvx_contract.to_string(),
            true,
            "mvx-msg-verifier".to_string(),
        );

        let mvx_verifier_set_contract = TMAddress::random(PREFIX);
        let mvx_verifier_set_config = Config::MvxVerifierSetVerifier {
            cosmwasm_contract: mvx_verifier_set_contract.clone(),
            proxy_url: Url::new_non_sensitive("http://localhost:7950").unwrap(),
        };

        validate_handler_info(
            mvx_verifier_set_config.handler_info(),
            "multiversx".to_string(),
            mvx_verifier_set_contract.to_string(),
            true,
            "mvx-verifier-set-verifier".to_string(),
        );
    }

    #[test]
    fn stellar_handlers_provide_correct_info() {
        let stellar_contract = TMAddress::random(PREFIX);
        let stellar_msg_config = Config::StellarMsgVerifier {
            cosmwasm_contract: stellar_contract.clone(),
            rpc_url: Url::new_non_sensitive("http://localhost:8000").unwrap(),
        };

        validate_handler_info(
            stellar_msg_config.handler_info(),
            "stellar".to_string(),
            stellar_contract.to_string(),
            true,
            "stellar-msg-verifier".to_string(),
        );

        let stellar_verifier_set_contract = TMAddress::random(PREFIX);
        let stellar_verifier_set_config = Config::StellarVerifierSetVerifier {
            cosmwasm_contract: stellar_verifier_set_contract.clone(),
            rpc_url: Url::new_non_sensitive("http://localhost:8000").unwrap(),
        };

        validate_handler_info(
            stellar_verifier_set_config.handler_info(),
            "stellar".to_string(),
            stellar_verifier_set_contract.to_string(),
            true,
            "stellar-verifier-set-verifier".to_string(),
        );
    }

    #[test]
    fn starknet_handlers_provide_correct_info() {
        let starknet_contract = TMAddress::random(PREFIX);
        let starknet_msg_config = Config::StarknetMsgVerifier {
            cosmwasm_contract: starknet_contract.clone(),
            rpc_url: Url::new_non_sensitive("http://localhost:5050").unwrap(),
        };

        validate_handler_info(
            starknet_msg_config.handler_info(),
            "starknet".to_string(),
            starknet_contract.to_string(),
            true,
            "starknet-msg-verifier".to_string(),
        );

        let starknet_verifier_set_contract = TMAddress::random(PREFIX);
        let starknet_verifier_set_config = Config::StarknetVerifierSetVerifier {
            cosmwasm_contract: starknet_verifier_set_contract.clone(),
            rpc_url: Url::new_non_sensitive("http://localhost:5050").unwrap(),
        };

        validate_handler_info(
            starknet_verifier_set_config.handler_info(),
            "starknet".to_string(),
            starknet_verifier_set_contract.to_string(),
            true,
            "starknet-verifier-set-verifier".to_string(),
        );
    }

    #[test]
    fn solana_handlers_provide_correct_info() {
        let solana_contract = TMAddress::random(PREFIX);
        let solana_msg_config = Config::SolanaMsgVerifier {
            chain_name: ChainName::from_str("solana").unwrap(),
            cosmwasm_contract: solana_contract.clone(),
            rpc_url: Url::new_non_sensitive("http://localhost:8899").unwrap(),
            rpc_timeout: None,
        };

        validate_handler_info(
            solana_msg_config.handler_info(),
            "solana".to_string(),
            solana_contract.to_string(),
            true,
            "solana-msg-verifier".to_string(),
        );

        let solana_verifier_set_contract = TMAddress::random(PREFIX);
        let solana_verifier_set_config = Config::SolanaVerifierSetVerifier {
            chain_name: ChainName::from_str("solana").unwrap(),
            cosmwasm_contract: solana_verifier_set_contract.clone(),
            rpc_url: Url::new_non_sensitive("http://localhost:8899").unwrap(),
            rpc_timeout: None,
        };

        validate_handler_info(
            solana_verifier_set_config.handler_info(),
            "solana".to_string(),
            solana_verifier_set_contract.to_string(),
            true,
            "solana-verifier-set-verifier".to_string(),
        );
    }

    fn validate_handler_info(
        handler_info: HandlerInfo,
        chain_name: String,
        verifier_id: String,
        cast_votes: bool,
        label: String,
    ) {
        assert_eq!(handler_info.chain_name, chain_name);
        assert_eq!(handler_info.verifier_id, verifier_id);
        assert_eq!(handler_info.cast_votes, cast_votes);
        assert_eq!(handler_info.label, label);
    }
}

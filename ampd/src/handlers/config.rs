use std::time::Duration;

use itertools::Itertools;
use router_api::ChainName;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_with::with_prefix;

use crate::evm::finalizer::Finalization;
use crate::types::TMAddress;
use crate::url::Url;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Chain {
    pub name: ChainName,
    pub rpc_url: Url,
    #[serde(default)]
    pub finalization: Finalization,
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
    MvxMsgVerifier {
        cosmwasm_contract: TMAddress,
        proxy_url: Url,
    },
    MvxVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        proxy_url: Url,
    },
    StellarMsgVerifier {
        cosmwasm_contract: TMAddress,
        http_url: Url,
    },
    StellarVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        http_url: Url,
    },
    StacksMsgVerifier {
        cosmwasm_contract: TMAddress,
        http_url: Url,
        its_address: String,
    },
    StacksVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        http_url: Url,
    },
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

    validate_evm_msg_verifier_configs::<D>(&configs)?;
    validate_evm_verifier_set_verifier_configs::<D>(&configs)?;

    ensure_unique_config!(&configs, Config::MultisigSigner, "Multisig signer")?;
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
    use serde_json::to_value;

    use crate::evm::finalizer::Finalization;
    use crate::handlers::config::{deserialize_handler_configs, Chain, Config};
    use crate::types::TMAddress;
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
            Config::MultisigSigner {
                cosmwasm_contract: TMAddress::random(PREFIX),
            },
            Config::MultisigSigner {
                cosmwasm_contract: TMAddress::random(PREFIX),
            },
        ];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Multisig signer config is allowed")
            )
        );

        let configs = vec![
            Config::SuiMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: "http://localhost:7545/".parse().unwrap(),
                rpc_timeout: None,
            },
            Config::SuiMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: "http://localhost:7545/".parse().unwrap(),
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
                rpc_url: "http://localhost:7545/".parse().unwrap(),
                rpc_timeout: None,
            },
            Config::SuiVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                rpc_url: "http://localhost:7545/".parse().unwrap(),
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
                proxy_url: "http://localhost:7545/".parse().unwrap(),
            },
            Config::MvxMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                proxy_url: "http://localhost:7545/".parse().unwrap(),
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
                proxy_url: "http://localhost:7545/".parse().unwrap(),
            },
            Config::MvxVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                proxy_url: "http://localhost:7545/".parse().unwrap(),
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
                http_url: "http://localhost:8080/".parse().unwrap(),
            },
            Config::StellarMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                http_url: "http://localhost:8080/".parse().unwrap(),
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
                http_url: "http://localhost:8080/".parse().unwrap(),
            },
            Config::StellarVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                http_url: "http://localhost:8080/".parse().unwrap(),
            },
        ];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Stellar verifier set verifier config is allowed")
            )
        );

        let configs = vec![
            Config::StacksMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                http_url: "http://localhost:8080/".parse().unwrap(),
                its_address: "its_address".to_string(),
            },
            Config::StacksMsgVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                http_url: "http://localhost:8080/".parse().unwrap(),
                its_address: "its_address".to_string(),
            },
        ];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Stacks message verifier config is allowed")
            )
        );

        let configs = vec![
            Config::StacksVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                http_url: "http://localhost:8080/".parse().unwrap(),
            },
            Config::StacksVerifierSetVerifier {
                cosmwasm_contract: TMAddress::random(PREFIX),
                http_url: "http://localhost:8080/".parse().unwrap(),
            },
        ];

        assert!(
            matches!(deserialize_handler_configs(to_value(configs).unwrap()),
                Err(e) if e.to_string().contains("only one Stacks verifier set verifier config is allowed")
            )
        );
    }
}

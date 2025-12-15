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
    SuiMsgVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
        #[serde(default, with = "humantime_serde::option")]
        rpc_timeout: Option<Duration>,
    },
    SuiVerifierSetVerifier {
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
        #[serde(default, with = "humantime_serde::option")]
        rpc_timeout: Option<Duration>,
    },
    XRPLMsgVerifier {
        cosmwasm_contract: TMAddress,
        chain_name: ChainName,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        chain_rpc_url: Url,
        #[serde(default, with = "humantime_serde::option")]
        rpc_timeout: Option<Duration>,
    },
    XRPLMultisigSigner {
        cosmwasm_contract: TMAddress,
        chain_name: ChainName,
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
    SolanaMsgVerifier {
        chain_name: ChainName,
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
        gateway_address: String,
        #[serde(default, with = "humantime_serde::option")]
        rpc_timeout: Option<Duration>,
    },
    SolanaVerifierSetVerifier {
        chain_name: ChainName,
        cosmwasm_contract: TMAddress,
        #[serde(deserialize_with = "Url::deserialize_sensitive")]
        rpc_url: Url,
        gateway_address: String,
        #[serde(default, with = "humantime_serde::option")]
        rpc_timeout: Option<Duration>,
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

    ensure_unique_config!(&configs, Config::XRPLMsgVerifier, "XRPL message verifier")?;
    ensure_unique_config!(&configs, Config::SuiMsgVerifier, "Sui message verifier")?;
    ensure_unique_config!(
        &configs,
        Config::SuiVerifierSetVerifier,
        "Sui verifier set verifier"
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
    use router_api::chain_name;
    use serde_json::to_value;

    use crate::handlers::config::{deserialize_handler_configs, Config};
    use crate::types::debug::REDACTED_VALUE;
    use crate::types::TMAddress;
    use crate::url::Url;
    use crate::PREFIX;

    const SOLANA: &str = "solana";

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
    }
}

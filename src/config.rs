use crate::broadcaster;
use crate::evm::{deserialize_evm_chain_configs, EvmChainConfig};
use crate::url::Url;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    pub tm_url: Url,
    pub broadcast: broadcaster::Config,
    #[serde(deserialize_with = "deserialize_evm_chain_configs")]
    pub evm_chain_configs: Vec<EvmChainConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tm_url: "tcp://localhost:26657".parse().unwrap(),
            broadcast: broadcaster::Config::default(),
            evm_chain_configs: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::evm::ChainName;

    #[test]
    fn deserialize_evm_configs() {
        let rpc_url = "http://localhost:7545/";
        let config_str = format!(
            "
            [[evm_chain_configs]]
            name = 'Ethereum'
            rpc_url = '{}'
            ",
            rpc_url
        );
        let cfg: Config = toml::from_str(config_str.as_str()).unwrap();

        assert_eq!(cfg.evm_chain_configs.len(), 1);
        let actual = cfg.evm_chain_configs.get(0).unwrap();
        assert_eq!(actual.name, ChainName::Ethereum);
        assert_eq!(actual.rpc_url.as_str(), rpc_url);
        assert_eq!(actual.l1_chain_name, None);
    }

    #[test]
    fn deserialize_url() {
        let expected_url = "tcp://localhost:26657";
        let cfg: Config = toml::from_str(format!("tm_url = '{expected_url}'").as_str()).unwrap();
        assert_eq!(cfg.tm_url.as_str(), expected_url)
    }

    #[test]
    fn fail_deserialization() {
        assert!(toml::from_str::<Config>("tm_url = 'some other string'").is_err());
        assert!(toml::from_str::<Config>("tm_url = 5").is_err());
    }
}

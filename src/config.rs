use serde::Deserialize;

use crate::broadcaster;
use crate::evm::{deserialize_evm_chain_configs, EvmChainConfig};
use crate::tofnd::Config as TofndConfig;
use crate::url::Url;
use crate::ECDSASigningKey;

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    pub tm_jsonrpc: Url,
    pub tm_grpc: Url,
    pub broadcast: broadcaster::Config,
    #[serde(deserialize_with = "deserialize_evm_chain_configs")]
    pub evm_chains: Vec<EvmChainConfig>,
    pub tofnd_config: TofndConfig,
    #[serde(with = "hex")]
    pub private_key: ECDSASigningKey,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tm_jsonrpc: "http://localhost:26657".parse().unwrap(),
            tm_grpc: "tcp://localhost:9090".parse().unwrap(),
            broadcast: broadcaster::Config::default(),
            evm_chains: vec![],
            tofnd_config: TofndConfig::default(),
            private_key: ECDSASigningKey::random(),
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmrs::bip32::secp256k1::elliptic_curve::rand_core::OsRng;

    use crate::{broadcaster::key::ECDSASigningKey, evm::ChainName};

    use super::Config;

    #[test]
    fn deserialize_evm_configs() {
        let rpc_url = "http://localhost:7545/";
        let voting_verifier = ECDSASigningKey::random().address();

        let config_str = format!(
            "
            [[evm_chains]]
            name = 'Ethereum'
            rpc_url = '{rpc_url}'
            voting_verifier = '{voting_verifier}'
            ",
        );
        let cfg: Config = toml::from_str(config_str.as_str()).unwrap();

        assert_eq!(cfg.evm_chains.len(), 1);
        let actual = cfg.evm_chains.get(0).unwrap();
        assert_eq!(actual.name, ChainName::Ethereum);
        assert_eq!(actual.rpc_url.as_str(), rpc_url);
        assert_eq!(actual.l1_chain_name, None);
        assert_eq!(actual.voting_verifier, voting_verifier);
    }

    #[test]
    fn deserialize_url() {
        let expected_url = "tcp://localhost:26657";
        let cfg: Config = toml::from_str(format!("tm_jsonrpc = '{expected_url}'").as_str()).unwrap();
        assert_eq!(cfg.tm_jsonrpc.as_str(), expected_url);

        let expected_url = "tcp://localhost:9090";
        let cfg: Config = toml::from_str(format!("tm_grpc = '{expected_url}'").as_str()).unwrap();
        assert_eq!(cfg.tm_grpc.as_str(), expected_url);
    }

    #[test]
    fn fail_deserialization() {
        assert!(toml::from_str::<Config>("tm_jsonrpc = 'some other string'").is_err());
        assert!(toml::from_str::<Config>("tm_jsonrpc = 5").is_err());
    }

    #[test]
    fn deserialize_tofnd_config() {
        let url = "http://localhost:50051/";

        let config_str = format!(
            "
            [tofnd_config]
            url = '{}'
            dail_timeout = '5s'
            ",
            url
        );

        let cfg: Config = toml::from_str(config_str.as_str()).unwrap();

        assert_eq!(cfg.tofnd_config.url.as_str(), url);
        assert_eq!(cfg.tofnd_config.dail_timeout.as_secs(), 5);
    }

    #[test]
    fn fail_deserialize_tofnd_config() {
        let invalid_timeout = "
            [tofnd_config]
            url = 'http://localhost:50051/'
            dail_timeout = '5x'
            ";

        assert!(toml::from_str::<Config>(invalid_timeout).is_err());
    }

    #[test]
    fn deserialize_private_key() {
        let random_key = ecdsa::SigningKey::random(&mut OsRng);
        let hex_private_key = hex::encode(random_key.to_bytes());
        let cfg: Config = toml::from_str(format!("private_key = '{hex_private_key}'").as_str()).unwrap();

        assert_eq!(
            cfg.private_key.public_key(),
            cosmrs::crypto::PublicKey::from(random_key.verifying_key())
        )
    }

    #[test]
    fn fail_deserialize_private_key() {
        assert!(toml::from_str::<Config>("private_key = 'a invalid key'").is_err());
    }
}

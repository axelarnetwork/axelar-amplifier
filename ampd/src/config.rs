use serde::Deserialize;

use crate::broadcaster;
use crate::handlers::{self, config::deserialize_handler_configs};
use crate::tofnd::Config as TofndConfig;
use crate::url::Url;

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    pub tm_jsonrpc: Url,
    pub tm_grpc: Url,
    pub broadcast: broadcaster::Config,
    #[serde(deserialize_with = "deserialize_handler_configs")]
    pub handlers: Vec<handlers::config::Config>,
    pub tofnd_config: TofndConfig,
    pub event_buffer_cap: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tm_jsonrpc: "http://localhost:26657".parse().unwrap(),
            tm_grpc: "tcp://localhost:9090".parse().unwrap(),
            broadcast: broadcaster::Config::default(),
            handlers: vec![],
            tofnd_config: TofndConfig::default(),
            event_buffer_cap: 100000,
        }
    }
}

#[cfg(test)]
mod tests {
    use ecdsa::SigningKey;
    use rand::rngs::OsRng;

    use super::Config;
    use crate::types::{PublicKey, TMAddress};

    #[test]
    fn deserialize_handlers() {
        let config_str = format!(
            "
            [[handlers]]
            type = 'EvmMsgVerifier'
            cosmwasm_contract = '{}'

            [handlers.chain]
            name = 'Ethereum'
            rpc_url = 'http://localhost:7545/'

            [[handlers]]
            type = 'EvmMsgVerifier'
            cosmwasm_contract = '{}'

            [handlers.chain]
            name = 'Polygon'
            rpc_url = 'http://localhost:7546/'

            [[handlers]]
            type = 'MultisigSigner'
            cosmwasm_contract = '{}'
            ",
            rand_tm_address(),
            rand_tm_address(),
            rand_tm_address(),
        );

        let cfg: Config = toml::from_str(config_str.as_str()).unwrap();
        assert_eq!(cfg.handlers.len(), 3);
    }

    #[test]
    fn deserialize_handlers_evm_msg_verifiers_with_the_same_chain_name() {
        let config_str = format!(
            "
            [[handlers]]
            type = 'EvmMsgVerifier'
            cosmwasm_contract = '{}'

            [handlers.chain]
            name = 'Ethereum'
            rpc_url = 'http://localhost:7545/'

            [[handlers]]
            type = 'EvmMsgVerifier'
            cosmwasm_contract = '{}'

            [handlers.chain]
            name = 'Ethereum'
            rpc_url = 'http://localhost:7546/'
            ",
            rand_tm_address(),
            rand_tm_address(),
        );

        assert!(toml::from_str::<Config>(config_str.as_str()).is_err());
    }

    #[test]
    fn deserialize_handlers_more_then_one_for_mulsitig_signer() {
        let config_str = format!(
            "
            [[handlers]]
            type = 'MultisigSigner'
            cosmwasm_contract = '{}'

            [[handlers]]
            type = 'MultisigSigner'
            cosmwasm_contract = '{}'
            ",
            rand_tm_address(),
            rand_tm_address(),
        );

        assert!(toml::from_str::<Config>(config_str.as_str()).is_err());
    }

    #[test]
    fn deserialize_url() {
        let expected_url = "tcp://localhost:26657";
        let cfg: Config =
            toml::from_str(format!("tm_jsonrpc = '{expected_url}'").as_str()).unwrap();
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
        let party_uid = "party_uid";
        let key_uid = "key_uid";

        let config_str = format!(
            "
            [tofnd_config]
            url = '{url}'
            party_uid = '{party_uid}'
            key_uid = '{key_uid}'
            ",
        );

        let cfg: Config = toml::from_str(config_str.as_str()).unwrap();

        assert_eq!(cfg.tofnd_config.url.as_str(), url);
        assert_eq!(cfg.tofnd_config.party_uid.as_str(), party_uid);
        assert_eq!(cfg.tofnd_config.key_uid.as_str(), key_uid);
    }

    fn rand_tm_address() -> TMAddress {
        PublicKey::from(SigningKey::random(&mut OsRng).verifying_key())
            .account_id("axelar")
            .unwrap()
            .into()
    }
}

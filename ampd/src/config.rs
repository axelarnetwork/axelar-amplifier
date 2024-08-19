use std::net::{Ipv4Addr, SocketAddrV4};

use serde::{Deserialize, Serialize};

use crate::commands::ServiceRegistryConfig;
use crate::handlers::config::deserialize_handler_configs;
use crate::handlers::{self};
use crate::tofnd::Config as TofndConfig;
use crate::url::Url;
use crate::{broadcaster, event_processor};

#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(default)]
pub struct Config {
    pub health_check_bind_addr: SocketAddrV4,
    pub tm_jsonrpc: Url,
    pub tm_grpc: Url,
    pub event_processor: event_processor::Config,
    pub broadcast: broadcaster::Config,
    #[serde(deserialize_with = "deserialize_handler_configs")]
    pub handlers: Vec<handlers::config::Config>,
    pub tofnd_config: TofndConfig,
    pub service_registry: ServiceRegistryConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tm_jsonrpc: "http://localhost:26657".parse().unwrap(),
            tm_grpc: "tcp://localhost:9090".parse().unwrap(),
            broadcast: broadcaster::Config::default(),
            handlers: vec![],
            tofnd_config: TofndConfig::default(),
            event_processor: event_processor::Config::default(),
            service_registry: ServiceRegistryConfig::default(),
            health_check_bind_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 3000),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Duration;

    use cosmrs::AccountId;
    use router_api::ChainName;

    use super::Config;
    use crate::evm::finalizer::Finalization;
    use crate::handlers::config::{Chain, Config as HandlerConfig};
    use crate::types::TMAddress;
    use crate::url::Url;

    const PREFIX: &str = "axelar";

    #[test]
    fn deserialize_handlers() {
        let config_str = format!(
            "
            [[handlers]]
            type = 'EvmMsgVerifier'
            cosmwasm_contract = '{}'
            chain_name = 'Ethereum'
            chain_rpc_url = 'http://localhost:7545/'

            [handlers.rpc_timeout]
            secs = 3
            nanos = 0

            [[handlers]]
            type = 'EvmMsgVerifier'
            cosmwasm_contract = '{}'
            chain_name = 'Polygon'
            chain_rpc_url = 'http://localhost:7546/'

            [[handlers]]
            type = 'EvmVerifierSetVerifier'
            cosmwasm_contract = '{}'
            chain_name = 'Ethereum'
            chain_rpc_url = 'http://localhost:7545/'

            [handlers.rpc_timeout]
            secs = 3
            nanos = 0

            [[handlers]]
            type = 'EvmVerifierSetVerifier'
            cosmwasm_contract = '{}'
            chain_name = 'Polygon'
            chain_rpc_url = 'http://localhost:7546/'

            [handlers.rpc_timeout]
            secs = 3
            nanos = 0

            [[handlers]]
            type = 'MultisigSigner'
            cosmwasm_contract = '{}'

            [[handlers]]
            type = 'SuiMsgVerifier'
            cosmwasm_contract = '{}'
            rpc_url = 'http://localhost:7545/'

            [handlers.rpc_timeout]
            secs = 3
            nanos = 0

            [[handlers]]
            type = 'MvxMsgVerifier'
            cosmwasm_contract = '{}'
            proxy_url = 'http://localhost:7545'

            [[handlers]]
            type = 'MvxVerifierSetVerifier'
            cosmwasm_contract = '{}'
            proxy_url = 'http://localhost:7545'
            ",
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
        );

        let cfg: Config = toml::from_str(config_str.as_str()).unwrap();
        assert_eq!(cfg.handlers.len(), 8);
    }

    #[test]
    fn deserialize_handlers_evm_msg_verifiers_with_the_same_chain_name() {
        let config_str = format!(
            "
            [[handlers]]
            type = 'EvmMsgVerifier'
            cosmwasm_contract = '{}'
            chain_name = 'Ethereum'
            chain_rpc_url = 'http://localhost:7545/'

            [[handlers]]
            type = 'EvmMsgVerifier'
            cosmwasm_contract = '{}'
            chain_name = 'Ethereum'
            chain_rpc_url = 'http://localhost:7546/'
            ",
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
        );

        assert!(toml::from_str::<Config>(config_str.as_str()).is_err());
    }

    #[test]
    fn deserialize_handlers_evm_verifier_set_verifiers_with_the_same_chain_name() {
        let config_str = format!(
            "
            [[handlers]]
            type = 'EvmVerifierSetVerifier'
            cosmwasm_contract = '{}'
            chain_name = 'Ethereum'
            chain_rpc_url = 'http://localhost:7545/'

            [[handlers]]
            type = 'EvmVerifierSetVerifier'
            cosmwasm_contract = '{}'
            chain_name = 'Ethereum'
            chain_rpc_url = 'http://localhost:7546/'
            ",
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
        );

        assert!(toml::from_str::<Config>(config_str.as_str()).is_err());
    }

    #[test]
    fn deserialize_handlers_more_then_one_for_multisig_signer() {
        let config_str = format!(
            "
            [[handlers]]
            type = 'MultisigSigner'
            cosmwasm_contract = '{}'

            [[handlers]]
            type = 'MultisigSigner'
            cosmwasm_contract = '{}'
            ",
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
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

    #[test]
    fn can_serialize_deserialize_config() {
        let cfg = config_template();

        let serialized = toml::to_string_pretty(&cfg).expect("should work");
        let deserialized: Config = toml::from_str(serialized.as_str()).expect("should work");

        assert_eq!(cfg, deserialized);
    }

    #[test]
    fn deserialize_config() {
        let cfg = toml::to_string_pretty(&config_template()).unwrap();

        let path = PathBuf::from_str("src/tests")
            .unwrap()
            .join("config_template.toml");

        // manually delete the file to create a new template before running the test
        if !path.exists() {
            let mut file = File::create(&path).unwrap();
            file.write_all(cfg.as_bytes()).unwrap();
        };

        let serialized = fs::read_to_string(path).unwrap();
        assert_eq!(cfg, serialized);
    }

    fn config_template() -> Config {
        Config {
            handlers: vec![
                HandlerConfig::EvmMsgVerifier {
                    chain: Chain {
                        name: ChainName::from_str("Ethereum").unwrap(),
                        finalization: Finalization::RPCFinalizedBlock,
                        rpc_url: Url::from_str("http://127.0.0.1").unwrap(),
                    },
                    rpc_timeout: Some(Duration::from_secs(3)),
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                },
                HandlerConfig::EvmVerifierSetVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    chain: Chain {
                        name: ChainName::from_str("Fantom").unwrap(),
                        finalization: Finalization::ConfirmationHeight,
                        rpc_url: Url::from_str("http://127.0.0.1").unwrap(),
                    },
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::MultisigSigner {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                },
                HandlerConfig::SuiMsgVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::from_str("http://127.0.0.1").unwrap(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::SuiVerifierSetVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::from_str("http://127.0.0.1").unwrap(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::MvxMsgVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    proxy_url: Url::from_str("http://127.0.0.1").unwrap(),
                },
                HandlerConfig::MvxVerifierSetVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    proxy_url: Url::from_str("http://127.0.0.1").unwrap(),
                },
            ],
            ..Config::default()
        }
    }
}

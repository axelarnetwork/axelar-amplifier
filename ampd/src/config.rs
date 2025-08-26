use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::commands::{RewardsConfig, ServiceRegistryConfig};
use crate::handlers::config::deserialize_handler_configs;
use crate::handlers::{self};
use crate::tofnd::Config as TofndConfig;
use crate::url::Url;
use crate::{broadcast, event_processor, grpc, monitoring};

#[derive(Deserialize, Serialize, PartialEq, Debug)]
#[serde(default)]
pub struct Config {
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    pub tm_jsonrpc: Url,
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    pub tm_grpc: Url,
    pub tm_grpc_timeout: Duration,
    pub event_processor: event_processor::Config,
    pub broadcast: broadcast::Config,
    #[serde(deserialize_with = "deserialize_handler_configs")]
    pub handlers: Vec<handlers::config::Config>,
    pub tofnd_config: TofndConfig,
    pub service_registry: ServiceRegistryConfig,
    pub rewards: RewardsConfig,
    #[serde(deserialize_with = "grpc::deserialize_config")]
    pub grpc: grpc::Config,
    pub monitoring_server: monitoring::Config,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tm_jsonrpc: Url::new_non_sensitive("http://localhost:26657")
                .expect("Url should be created validly"),
            tm_grpc: Url::new_non_sensitive("tcp://localhost:9090")
                .expect("Url should be created validly"),
            tm_grpc_timeout: Duration::from_secs(5),
            broadcast: broadcast::Config::default(),
            handlers: vec![],
            tofnd_config: TofndConfig::default(),
            event_processor: event_processor::Config::default(),
            service_registry: ServiceRegistryConfig::default(),
            rewards: RewardsConfig::default(),
            grpc: grpc::Config::default(),
            monitoring_server: monitoring::Config::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Duration;

    use cosmrs::AccountId;
    use router_api::chain_name;

    use super::Config;
    use crate::evm::finalizer::Finalization;
    use crate::handlers::config::{Chain, Config as HandlerConfig};
    use crate::types::TMAddress;
    use crate::url::Url;

    const PREFIX: &str = "axelar";

    #[test]
    fn deserialize_valid_grpc_config() {
        let ip_addr = "0.0.0.0";
        let port = 9091;
        let global_concurrency_limit = 2048;
        let concurrency_limit_per_connection = 256;
        let request_timeout = "30s";

        let config_str = format!(
            "
            [grpc]
            ip_addr = '{ip_addr}'
            port = {port}
            global_concurrency_limit = {global_concurrency_limit}
            concurrency_limit_per_connection = {concurrency_limit_per_connection}
            request_timeout = '{request_timeout}'
            ",
        );
        let cfg: Config = toml::from_str(config_str.as_str()).unwrap();

        goldie::assert_json!(cfg);
    }

    #[test]
    fn deserialize_invalid_grpc_config() {
        let ip_addr = "invalid_ip";
        let port = 9091;
        let global_concurrency_limit = 2048;
        let concurrency_limit_per_connection = 256;
        let request_timeout = "30s";

        let config_str = format!(
            "
            [grpc]
            ip_addr = '{ip_addr}'
            port = {port}
            global_concurrency_limit = {global_concurrency_limit}
            concurrency_limit_per_connection = {concurrency_limit_per_connection}
            request_timeout = '{request_timeout}'
            ",
        );
        let cfg: Result<Config, _> = toml::from_str(config_str.as_str());
        assert!(cfg.is_err());

        let ip_addr = "0.0.0.0";
        let port = "invalid_port";
        let global_concurrency_limit = 2048;
        let concurrency_limit_per_connection = 256;
        let request_timeout = "30s";

        let config_str = format!(
            "
            [grpc]
            ip_addr = '{ip_addr}'
            port = {port}
            global_concurrency_limit = {global_concurrency_limit}
            concurrency_limit_per_connection = {concurrency_limit_per_connection}
            request_timeout = '{request_timeout}'
            ",
        );
        let cfg: Result<Config, _> = toml::from_str(config_str.as_str());
        assert!(cfg.is_err());

        let ip_addr = "0.0.0.0";
        let port = 9090;
        let global_concurrency_limit = 0;
        let concurrency_limit_per_connection = 256;
        let request_timeout = "30s";

        let config_str = format!(
            "
            [grpc]
            ip_addr = '{ip_addr}'
            port = {port}
            global_concurrency_limit = {global_concurrency_limit}
            concurrency_limit_per_connection = {concurrency_limit_per_connection}
            request_timeout = '{request_timeout}'
            ",
        );
        let cfg: Result<Config, _> = toml::from_str(config_str.as_str());
        assert!(cfg.is_err());

        let ip_addr = "0.0.0.0";
        let port = 9090;
        let global_concurrency_limit = 2048;
        let concurrency_limit_per_connection = 0;
        let request_timeout = "30s";

        let config_str = format!(
            "
            [grpc]
            ip_addr = '{ip_addr}'
            port = {port}
            global_concurrency_limit = {global_concurrency_limit}
            concurrency_limit_per_connection = {concurrency_limit_per_connection}
            request_timeout = '{request_timeout}'
            ",
        );
        let cfg: Result<Config, _> = toml::from_str(config_str.as_str());
        assert!(cfg.is_err());

        let ip_addr = "0.0.0.0";
        let port = 9090;
        let global_concurrency_limit = 100;
        let concurrency_limit_per_connection = 200;
        let request_timeout = "30s";

        let config_str = format!(
            "
            [grpc]
            ip_addr = '{ip_addr}'
            port = {port}
            global_concurrency_limit = {global_concurrency_limit}
            concurrency_limit_per_connection = {concurrency_limit_per_connection}
            request_timeout = '{request_timeout}'
            ",
        );
        let cfg: Result<Config, _> = toml::from_str(config_str.as_str());
        assert!(cfg.is_err());

        let ip_addr = "0.0.0.0";
        let port = 9090;
        let global_concurrency_limit = 100;
        let concurrency_limit_per_connection = 100;
        let invalid_request_timeout = "invalid_timeout";

        let config_str = format!(
            "
            [grpc]
            ip_addr = '{ip_addr}'
            port = {port}
            global_concurrency_limit = {global_concurrency_limit}
            concurrency_limit_per_connection = {concurrency_limit_per_connection}
            request_timeout = '{invalid_request_timeout}'
            ",
        );
        let cfg: Result<Config, _> = toml::from_str(config_str.as_str());
        assert!(cfg.is_err());
    }

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
            type = 'EvmEventVerifier'
            cosmwasm_contract = '{}'
            chain_name = 'Ethereum'
            chain_rpc_url = 'http://localhost:7545/'
            chain_finalization = 'RPCFinalizedBlock'
            confirmation_height = 15

            [handlers.rpc_timeout]
            secs = 3
            nanos = 0

            [[handlers]]
            type = 'MultisigSigner'
            cosmwasm_contract = '{}'
            chain_name = 'Ethereum'

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

            [[handlers]]
            type = 'StellarMsgVerifier'
            cosmwasm_contract = '{}'
            rpc_url = 'http://localhost:7545'

            [[handlers]]
            type = 'StellarVerifierSetVerifier'
            cosmwasm_contract = '{}'
            rpc_url = 'http://localhost:7545'

            [[handlers]]
            type = 'StarknetMsgVerifier'
            cosmwasm_contract = '{}'
            rpc_url = 'http://localhost:7545'

            [[handlers]]
            type = 'StarknetVerifierSetVerifier'
            cosmwasm_contract = '{}'
            rpc_url = 'http://localhost:7545'

            [[handlers]]
            type = 'SolanaMsgVerifier'
            chain_name = 'solana'
            cosmwasm_contract = '{}'
            rpc_url = 'http://127.0.0.1'

            [handlers.rpc_timeout]
            secs = 3
            nanos = 0

            [[handlers]]
            type = 'SolanaVerifierSetVerifier'
            chain_name = 'solana'
            cosmwasm_contract = '{}'
            rpc_url = 'http://127.0.0.1'

            [handlers.rpc_timeout]
            secs = 3
            nanos = 0

            [[handlers]]
            type = 'StacksMsgVerifier'
            chain_name = 'stacks'
            cosmwasm_contract = '{}'
            rpc_url = 'http://localhost:8000'

            [handlers.rpc_timeout]
            secs = 3
            nanos = 0

            [[handlers]]
            type = 'StacksVerifierSetVerifier'
            chain_name = 'stacks'
            cosmwasm_contract = '{}'
            rpc_url = 'http://localhost:8000'

            [handlers.rpc_timeout]
            secs = 3
            nanos = 0
            ",
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
            TMAddress::random(PREFIX),
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
        assert_eq!(cfg.handlers.len(), 17);
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

            [tofnd_config.timeout]
            secs = 5
            nanos = 0
            ",
        );

        let cfg: Config = toml::from_str(config_str.as_str()).unwrap();

        assert_eq!(cfg.tofnd_config.url.as_str(), url);
        assert_eq!(cfg.tofnd_config.party_uid.as_str(), party_uid);
        assert_eq!(cfg.tofnd_config.key_uid.as_str(), key_uid);
    }
    #[test]
    fn serialization_roundtrip_preserves_data() {
        let cfg = config_template();
        let serialized1 = toml::to_string_pretty(&cfg).expect("should work");
        let deserialized: Config = toml::from_str(serialized1.as_str()).expect("should work");
        let serialized2 = toml::to_string_pretty(&deserialized).expect("should work");
        assert_eq!(serialized1, serialized2);
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
                        name: chain_name!("Ethereum"),
                        finalization: Finalization::RPCFinalizedBlock,
                        rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
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
                        name: chain_name!("Fantom"),
                        finalization: Finalization::ConfirmationHeight,
                        rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    },
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::EvmEventVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    chain: Chain {
                        name: chain_name!("Polygon"),
                        finalization: Finalization::RPCFinalizedBlock,
                        rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    },
                    rpc_timeout: Some(Duration::from_secs(3)),
                    confirmation_height: 15,
                },
                HandlerConfig::MultisigSigner {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    chain_name: chain_name!("Ethereum"),
                },
                HandlerConfig::SuiMsgVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::SuiVerifierSetVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::MvxMsgVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    proxy_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                },
                HandlerConfig::MvxVerifierSetVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    proxy_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                },
                HandlerConfig::StellarMsgVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                },
                HandlerConfig::StellarVerifierSetVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                },
                HandlerConfig::StarknetMsgVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                },
                HandlerConfig::StarknetVerifierSetVerifier {
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                },
                HandlerConfig::SolanaMsgVerifier {
                    chain_name: chain_name!("solana"),
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::SolanaVerifierSetVerifier {
                    chain_name: chain_name!("solana"),
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::StacksMsgVerifier {
                    chain_name: chain_name!("stacks"),
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::StacksVerifierSetVerifier {
                    chain_name: chain_name!("stacks"),
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
            ],
            ..Config::default()
        }
    }

    #[test]
    fn deserialize_monitoring_server_config_with_bind_address_and_enabled() {
        let bind_address = "0.0.0.0:3001";
        let config_str = format!(
            "
            [monitoring_server]
            enabled = true
            bind_address = '{bind_address}'
            ",
        );
        let cfg: Config = toml::from_str(&config_str).unwrap();
        assert_eq!(
            cfg.monitoring_server.bind_address,
            Some(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 3001))
        );
    }

    #[test]
    fn deserialize_monitoring_server_config_without_bind_address_enabled() {
        let config_str = "
            [monitoring_server]
            enabled = true
            ";
        let cfg: Config = toml::from_str(config_str).unwrap();
        assert_eq!(
            cfg.monitoring_server.bind_address,
            Some(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000))
        );
    }

    #[test]
    fn deserialize_monitoring_server_config_disabled() {
        let config_str = "
            [monitoring_server]
            enabled = false
            ";
        let cfg: Config = toml::from_str(config_str).unwrap();
        assert_eq!(cfg.monitoring_server.bind_address, None);
    }
}

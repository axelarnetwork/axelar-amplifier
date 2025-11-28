use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::commands::{RewardsConfig, ServiceRegistryConfig};
use crate::handlers::config::deserialize_handler_configs;
use crate::handlers::{self};
use crate::tofnd::Config as TofndConfig;
use crate::url::Url;
use crate::{broadcast, event_processor, event_sub, grpc, monitoring, tm_client};

/// Root configuration for the ampd daemon.
#[derive(Deserialize, Serialize, PartialEq, Debug)]
#[serde(default)]
pub struct Config {
    /// Tendermint JSON-RPC endpoint URL (e.g., "http://localhost:26657").
    ///
    /// Used for subscribing to block events and querying block data.
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    pub tm_jsonrpc: Url,

    /// Tendermint gRPC endpoint URL (e.g., "tcp://localhost:9090").
    ///
    /// Used for broadcasting transactions and querying chain state.
    #[serde(deserialize_with = "Url::deserialize_sensitive")]
    pub tm_grpc: Url,

    /// Default timeout for external RPC calls (e.g., to EVM chains).
    ///
    /// Individual handlers may override this with their own `rpc_timeout` setting.
    #[serde(with = "humantime_serde")]
    pub default_rpc_timeout: Duration,

    /// Timeout for Tendermint gRPC calls.
    ///
    /// Applied to transaction broadcasts, account queries, and other gRPC operations.
    #[serde(with = "humantime_serde")]
    pub tm_grpc_timeout: Duration,

    /// Configuration for processing events from the Axelar chain.
    pub event_processor: event_processor::Config,

    /// Configuration for broadcasting transactions to the Axelar chain.
    pub broadcast: broadcast::Config,

    /// Handler configurations for different chain integrations.
    ///
    /// Each handler processes events for a specific chain (e.g., EVM, Sui, Solana).
    #[serde(deserialize_with = "deserialize_handler_configs")]
    pub handlers: Vec<handlers::config::Config>,

    /// Configuration for connecting to the tofnd signing service.
    pub tofnd_config: TofndConfig,

    /// Service registry contract configuration.
    pub service_registry: ServiceRegistryConfig,

    /// Rewards contract configuration.
    pub rewards: RewardsConfig,

    /// gRPC server configuration for external clients.
    ///
    /// This allows separate event handler processes to hook into the base ampd process.
    #[serde(deserialize_with = "grpc::deserialize_config")]
    pub grpc: grpc::Config,

    /// Monitoring/metrics server configuration.
    pub monitoring_server: monitoring::Config,

    /// Configuration for subscribing to Axelar chain events.
    pub event_sub: event_sub::Config,

    /// Tendermint client retry configuration.
    pub tm_client: tm_client::Config,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tm_jsonrpc: Url::new_non_sensitive("http://localhost:26657")
                .expect("Url should be created validly"),
            tm_grpc: Url::new_non_sensitive("tcp://localhost:9090")
                .expect("Url should be created validly"),
            default_rpc_timeout: Duration::from_secs(3),
            tm_grpc_timeout: Duration::from_secs(5),
            broadcast: broadcast::Config::default(),
            handlers: vec![],
            tofnd_config: TofndConfig::default(),
            event_processor: event_processor::Config::default(),
            service_registry: ServiceRegistryConfig::default(),
            rewards: RewardsConfig::default(),
            grpc: grpc::Config::default(),
            monitoring_server: monitoring::Config::default(),
            event_sub: event_sub::Config::default(),
            tm_client: tm_client::Config::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cosmrs::AccountId;
    use router_api::chain_name;

    use super::Config;
    use crate::evm::finalizer::Finalization;
    use crate::grpc;
    use crate::handlers::config::{Chain, Config as HandlerConfig};
    use crate::types::TMAddress;
    use crate::url::Url;

    const PREFIX: &str = "axelar";
    const SOLANA: &str = "solana";
    const STACKS: &str = "stacks";

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
    fn fail_deserialization() {
        assert!(toml::from_str::<Config>("tm_jsonrpc = 'some other string'").is_err());
        assert!(toml::from_str::<Config>("tm_jsonrpc = 5").is_err());
    }

    /// Tests that config serialization and deserialization is lossless.
    ///
    /// This test:
    /// 1. Creates a config with all defaults plus dummy values for fields without good defaults
    /// 2. Serializes it to TOML and asserts it matches the golden file
    /// 3. Deserializes the TOML back and asserts it equals the original config
    /// 4. Writes the serialized config to src/tests/config_template.toml for documentation
    #[test]
    fn config_serialization_roundtrip() {
        let original_config = config_with_dummy_values();
        let serialized =
            toml::to_string_pretty(&original_config).expect("serialization should work");

        goldie::assert!(&serialized);

        let deserialized: Config =
            toml::from_str(&serialized).expect("deserialization should work");
        assert_eq!(original_config, deserialized);

        // Also write to config_template.toml for documentation purposes
        let template_path = std::path::PathBuf::from("src/tests/config_template.toml");
        std::fs::write(&template_path, &serialized).expect("failed to write config_template.toml");
    }

    fn config_with_dummy_values() -> Config {
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
                    chain_name: chain_name!(SOLANA),
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    gateway_address: "11111111111111111111111111111112".to_string(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::SolanaVerifierSetVerifier {
                    chain_name: chain_name!(SOLANA),
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    gateway_address: "11111111111111111111111111111112".to_string(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::StacksMsgVerifier {
                    chain_name: chain_name!(STACKS),
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
                HandlerConfig::StacksVerifierSetVerifier {
                    chain_name: chain_name!(STACKS),
                    cosmwasm_contract: TMAddress::from(
                        AccountId::new("axelar", &[0u8; 32]).unwrap(),
                    ),
                    rpc_url: Url::new_non_sensitive("http://127.0.0.1").unwrap(),
                    rpc_timeout: Some(Duration::from_secs(3)),
                },
            ],
            grpc: grpc::Config {
                blockchain_service: grpc::BlockchainServiceConfig {
                    chains: vec![
                        grpc::BlockchainServiceChainConfig {
                            chain_name: chain_name!("ethereum"),
                            voting_verifier: TMAddress::from(
                                AccountId::new("axelar", &[0u8; 32]).unwrap(),
                            ),
                            multisig_prover: TMAddress::from(
                                AccountId::new("axelar", &[0u8; 32]).unwrap(),
                            ),
                            multisig: TMAddress::from(
                                AccountId::new("axelar", &[0u8; 32]).unwrap(),
                            ),
                        },
                        grpc::BlockchainServiceChainConfig {
                            chain_name: chain_name!("solana"),
                            voting_verifier: TMAddress::from(
                                AccountId::new("axelar", &[0u8; 32]).unwrap(),
                            ),
                            multisig_prover: TMAddress::from(
                                AccountId::new("axelar", &[0u8; 32]).unwrap(),
                            ),
                            multisig: TMAddress::from(
                                AccountId::new("axelar", &[0u8; 32]).unwrap(),
                            ),
                        },
                        grpc::BlockchainServiceChainConfig {
                            chain_name: chain_name!("flow"),
                            voting_verifier: TMAddress::from(
                                AccountId::new("axelar", &[0u8; 32]).unwrap(),
                            ),
                            multisig_prover: TMAddress::from(
                                AccountId::new("axelar", &[0u8; 32]).unwrap(),
                            ),
                            multisig: TMAddress::from(
                                AccountId::new("axelar", &[0u8; 32]).unwrap(),
                            ),
                        },
                    ],
                },
                ..grpc::Config::default()
            },
            ..Config::default()
        }
    }
}

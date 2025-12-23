use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::commands::{RewardsConfig, ServiceRegistryConfig};
use crate::tofnd::Config as TofndConfig;
use crate::url::Url;
use crate::{broadcast, event_sub, grpc, monitoring, tm_client};

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

    /// Timeout for Tendermint gRPC calls.
    ///
    /// Applied to transaction broadcasts, account queries, and other gRPC operations.
    #[serde(with = "humantime_serde")]
    pub tm_grpc_timeout: Duration,

    /// Configuration for broadcasting transactions to the Axelar chain.
    pub broadcast: broadcast::Config,

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
            tm_grpc_timeout: Duration::from_secs(5),
            broadcast: broadcast::Config::default(),
            tofnd_config: TofndConfig::default(),
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
    use cosmrs::AccountId;
    use router_api::chain_name;

    use super::Config;
    use crate::grpc;
    use crate::types::TMAddress;

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
                            event_verifier: None,
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
                            event_verifier: None,
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
                            event_verifier: None,
                        },
                    ],
                },
                ..grpc::Config::default()
            },
            ..Config::default()
        }
    }
}

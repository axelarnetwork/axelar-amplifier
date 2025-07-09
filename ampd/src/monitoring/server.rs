use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use axum::routing::MethodRouter;
use axum::Router;
use error_stack::{Result, ResultExt};
use futures::future::join_all;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::monitoring::endpoints::status;
use crate::monitoring::metrics;

/// Errors that can occur during monitoring server operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to start monitoring server")]
    Start,
    #[error("monitoring server failed while running")]
    WhileRunning,
}

/// Configuration for the monitoring server
///
/// Controls whether the monitoring server is enabled and on which address it binds.
/// When `bind_address` is `None`, the server is disabled.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Config {
    /// The address to bind the monitoring server to.
    /// When `None`, the server is disabled.
    pub bind_address: Option<SocketAddrV4>,
}

impl Config {
    /// Creates a new configuration with monitoring enabled using the default bind address
    ///
    /// The default bind address is `127.0.0.1:3000`.
    pub fn enabled() -> Self {
        Self {
            bind_address: Some(Self::default_bind_addr()),
        }
    }

    fn default_bind_addr() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000)
    }
}

// Custom serialization to make the state of the monitoring server more explicit in a config file
impl Serialize for Config {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct ConfigCompat {
            enabled: bool,
            bind_address: SocketAddrV4,
        }

        let compat = ConfigCompat {
            enabled: self.bind_address.is_some(),
            bind_address: self.bind_address.unwrap_or_else(Self::default_bind_addr),
        };

        compat.serialize(serializer)
    }
}

// Custom deserialization to handle the more explicit state of the monitoring server from a config file
impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ConfigCompat {
            #[serde(default)]
            enabled: bool,
            #[serde(default = "Config::default_bind_addr")]
            bind_address: SocketAddrV4,
        }

        let compat = ConfigCompat::deserialize(deserializer)?;

        Ok(Config {
            bind_address: compat.enabled.then_some(compat.bind_address),
        })
    }
}

/// Client for interacting with the monitoring system
///
/// Provides access to metrics collection and other monitoring functionality.
/// This client can be cloned and used across different parts of the application.
#[derive(Clone)]
pub struct Client {
    metrics_client: metrics::Client,
}

impl Client {
    /// Returns a reference to the metrics client
    ///
    /// Use this to record metrics events throughout the application.
    pub fn metrics(&self) -> &metrics::Client {
        &self.metrics_client
    }
}

/// The monitoring server that can run in either disabled or enabled mode
///
/// - `Disabled`: Server is disabled, no HTTP endpoints are exposed
/// - `Enabled`: Server is enabled and runs HTTP endpoints for metrics and status
pub enum Server {
    Disabled,
    Enabled { server: HttpServer },
}

impl Server {
    /// Creates a new monitoring server and client pair
    ///
    /// # Arguments
    ///
    /// * `bind_address` - Optional socket address to bind the server to.
    ///   If `None`, creates a disabled server that doesn't expose HTTP endpoints.
    ///
    /// # Returns
    ///
    /// A tuple containing the server instance and a client for interacting with it.
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot be created or if metrics endpoints
    /// cannot be initialized.
    pub fn new(bind_address: Option<SocketAddrV4>) -> Result<(Server, Client), super::Error> {
        match bind_address {
            Some(addr) => Self::create_server_with_client(addr),
            None => {
                info!("monitoring server is disabled");
                Ok((
                    Server::Disabled,
                    Client {
                        metrics_client: metrics::Client::Disabled,
                    },
                ))
            }
        }
    }

    fn create_server_with_client(bind_address: SocketAddrV4) -> Result<(Server, Client), Error> {
        let status_router = status::create_endpoint();
        let (metrics_router, metrics_process, metrics_client) = metrics::create_endpoint();

        let server = Server::Enabled {
            server: HttpServer {
                bind_address,
                routes: HashMap::from([("/status", status_router), ("/metrics", metrics_router)]),
                endpoint_handles: vec![Box::new(|cancel| metrics_process.run(cancel))],
            },
        };

        let client = Client { metrics_client };

        Ok((server, client))
    }

    /// Runs the monitoring server until the cancellation token is triggered
    ///
    /// # Arguments
    ///
    /// * `cancel` - Cancellation token to gracefully shut down the server
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful shutdown, or an error if the server
    /// fails to start or encounters an error while running.
    ///
    /// # Behavior
    ///
    /// - For `Disabled` servers: Simply waits for cancellation
    /// - For `Enabled` servers: Starts HTTP server and serves requests until cancelled
    pub async fn run(self, cancel: CancellationToken) -> Result<(), Error> {
        match self {
            Server::Disabled => {
                cancel.cancelled().await;
                Ok(())
            }
            Server::Enabled { server } => server.run_server(cancel).await,
        }
    }
}

/// HTTP server implementation for monitoring endpoints
///
/// This struct contains the actual HTTP server implementation that serves
/// monitoring endpoints like `/metrics` and `/status`.
pub struct HttpServer {
    bind_address: SocketAddrV4,
    routes: HashMap<&'static str, MethodRouter>,
    endpoint_handles: Vec<Box<dyn FnOnce(CancellationToken) -> JoinHandle<()> + Send>>,
}

impl HttpServer {
    async fn run_server(self, cancel: CancellationToken) -> Result<(), Error> {
        info!(
            address = self.bind_address.to_string(),
            "starting monitoring server"
        );

        let router = self
            .routes
            .into_iter()
            .fold(Router::new(), |router, (path, method_router)| {
                router.route(path, method_router)
            });

        let server_cancel = cancel.clone();
        let handles = join_all(
            self.endpoint_handles
                .into_iter()
                .map(|handle| handle(cancel.clone())),
        );

        let listener = tokio::net::TcpListener::bind(self.bind_address)
            .await
            .change_context(Error::Start)?;

        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                server_cancel.cancelled().await;
                info!("shutting down monitoring server")
            })
            .await
            .change_context(Error::WhileRunning)?;

        // Wait for endpoints to shut down. Otherwise, we lose control over their runtime,
        // which could lead to undefined behaviour during shutdown
        _ = handles.await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::time::Duration;

    use rand::random;
    use tokio::test as async_test;

    use super::*;
    use crate::monitoring::endpoints::status::Status;

    #[test]
    fn ensure_correct_default_config() {
        let enabled_config = Config::enabled();
        let disabled_config = Config::default();

        let enabled_serialized = toml::to_string(&enabled_config).unwrap();
        let disabled_serialized = toml::to_string(&disabled_config).unwrap();

        let output = format!(
            "Enabled Config:\n{:?}\n\nDisabled Config:\n{:?}\n\nEnabled Serialized:\n{}\n\nDisabled Serialized:\n{}",
            enabled_config, disabled_config, enabled_serialized, disabled_serialized
        );

        goldie::assert!(output);
    }

    #[test]
    // Because this config has custom serialization, we need to ensure it can be parsed correctly event from environment variables
    fn config_can_be_parsed_from_env_variable() {
        use config::{Config as cfg, Environment};

        // Test parsing enabled config from environment variable
        env::set_var("TEST_MONITORING_ENABLED", "true");
        env::set_var("TEST_MONITORING_BIND_ADDRESS", "127.0.0.1:4000");

        let enabled_config: Config = cfg::builder()
            .add_source(Environment::with_prefix("TEST_MONITORING"))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(
            enabled_config.bind_address,
            Some(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 4000))
        );

        // Test parsing disabled config from environment variable
        env::set_var("TEST_MONITORING_ENABLED", "false");
        let disabled_config: Config = cfg::builder()
            .add_source(Environment::with_prefix("TEST_MONITORING"))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(disabled_config.bind_address, None);

        // Clean up
        env::remove_var("TEST_MONITORING_ENABLED");
        env::remove_var("TEST_MONITORING_BIND_ADDRESS");
    }

    #[test]
    fn disabled_client_discards_messages_without_error() {
        let (_, client) = Server::new(None).unwrap(); // Creates disabled server and client

        // Should succeed without doing anything
        let result = client.metrics().record_metric(metrics::Msg::BlockReceived);
        assert!(
            result.is_ok(),
            "disabled client should discard messages successfully"
        );

        // Multiple messages should also work
        for _ in 0..100 {
            let result = client.metrics().record_metric(metrics::Msg::BlockReceived);
            assert!(
                result.is_ok(),
                "disabled client should handle multiple messages"
            );
        }
    }

    #[async_test]
    async fn disabled_server_shuts_down_when_cancelled() {
        let (server, _) = Server::new(None).unwrap(); // Creates disabled server
        let cancel = CancellationToken::new();

        let handle = tokio::spawn(server.run(cancel.clone()));
        cancel.cancel();
        let result = handle.await;

        assert!(
            result.is_ok(),
            "disabled server should shut down without panicking"
        );
        assert!(
            result.unwrap().is_ok(),
            "disabled server should shut down without errors"
        );
    }

    #[async_test]
    async fn server_startup_fails_when_address_unavailable() {
        // First, bind to a specific port to make it unavailable
        let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3001);
        let _listener = tokio::net::TcpListener::bind(addr).await.unwrap();

        // Create a server on the same address - creation should succeed
        let (server, _) = Server::new(Some(addr)).unwrap();

        // But running the server should fail
        let cancel = CancellationToken::new();
        let result = server.run(cancel).await;
        assert!(
            result.is_err(),
            "Server run should fail when address is unavailable"
        );

        let error = result.unwrap_err();

        // lower level errors can contain os error codes that are different on different platforms, so only check the current context
        goldie::assert!(error.current_context().to_string());
    }

    #[async_test(start_paused = true)]
    async fn enabled_server_responds_to_status_endpoint_and_shuts_down_gracefully() {
        let bind_address = localhost_with_random_port();
        let (server, _) = Server::new(bind_address).unwrap();
        let cancel = CancellationToken::new();

        let server_handle = tokio::spawn(server.run(cancel.clone()));

        let status_url = create_endpoint_url(bind_address, "status");

        tokio::time::sleep(Duration::from_secs(1)).await;

        let response = reqwest::get(status_url.clone()).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, response.status());

        let status = response.json::<Status>().await.unwrap();
        assert!(status.ok);

        cancel.cancel();
        _ = server_handle.await;

        assert!(
            reqwest::get(status_url).await.unwrap_err().is_connect(),
            "monitor server should be closed by now"
        )
    }

    #[async_test(start_paused = true)]
    async fn enabled_server_continues_serving_after_all_metrics_clients_dropped() {
        let bind_address = localhost_with_random_port();
        let (server, monitoring_client) = Server::new(bind_address).unwrap();
        let cancel = CancellationToken::new();

        let server_handle = tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        send_multiple_metrics(&monitoring_client, metrics::Msg::BlockReceived, 3);
        drop(monitoring_client);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let metrics_url = create_endpoint_url(bind_address, "metrics");
        let response = reqwest::get(metrics_url.clone()).await;
        assert!(
            response.is_ok(),
            "metrics server is not responding after all clients dropped"
        );

        cancel.cancel();
        _ = server_handle.await;

        assert!(
            reqwest::get(metrics_url).await.unwrap_err().is_connect(),
            "monitor server should be closed by now"
        )
    }

    #[async_test(start_paused = true)]
    async fn metrics_endpoint_increments_counters_when_messages_sent() {
        let bind_address = localhost_with_random_port();
        let (server, monitoring_client) = Server::new(bind_address).unwrap();
        let cancel = CancellationToken::new();

        let server_handle = tokio::spawn(server.run(cancel.clone()));
        let metrics_url = create_endpoint_url(bind_address, "metrics");

        tokio::time::sleep(Duration::from_millis(100)).await;

        let initial_metrics = reqwest::get(metrics_url.clone()).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, initial_metrics.status());
        let initial_text = initial_metrics.text().await.unwrap();

        let verifier_id = "verifier_id".to_string();
        let chain_name = "chain_name".to_string();

        send_multiple_metrics(&monitoring_client, metrics::Msg::BlockReceived, 3);
        send_multiple_metrics(
            &monitoring_client,
            metrics::Msg::VoteCastSucceeded {
                verifier_id: verifier_id.clone(),
                chain_name: chain_name.clone(),
            },
            2,
        );
        send_multiple_metrics(
            &monitoring_client,
            metrics::Msg::VoteFailed {
                verifier_id: verifier_id.clone(),
                chain_name: chain_name.clone(),
            },
            1,
        );

        tokio::time::sleep(Duration::from_millis(100)).await;

        let updated_metrics = reqwest::get(metrics_url).await.unwrap();
        let updated_text = updated_metrics.text().await.unwrap();

        let output = format!(
            "Initial Metrics:\n{}\n\nUpdated Metrics:\n{}",
            initial_text, updated_text
        );

        goldie::assert!(output);
        cancel.cancel();
        _ = server_handle.await;
    }

    #[async_test(start_paused = true)]
    async fn enabled_server_shuts_down_gracefully_when_cancellation_token_triggered() {
        let (server, monitoring_client) = Server::new(localhost_with_random_port()).unwrap();
        let cancel = CancellationToken::new();

        let server_handle = tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        send_multiple_metrics(&monitoring_client, metrics::Msg::BlockReceived, 2);

        cancel.cancel();
        let shutdown_result = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
        assert!(
            shutdown_result.is_ok(),
            "server should shut down gracefully"
        );
        let shutdown_result = shutdown_result.unwrap();
        assert!(
            shutdown_result.is_ok(),
            "server should shut down without panicking"
        );

        assert!(
            shutdown_result.unwrap().is_ok(),
            "server should shut down without errors"
        );

        tokio::time::sleep(Duration::from_millis(100)).await;

        // client should not be able to send message after server shutdown
        let send_result = monitoring_client
            .metrics()
            .record_metric(metrics::Msg::BlockReceived);
        assert!(
            send_result.is_err(),
            "client should not be able to send messages after server shutdown"
        );
    }

    #[async_test(start_paused = true)]
    async fn enabled_server_handles_concurrent_metrics_requests_correctly() {
        let bind_address = localhost_with_random_port();
        let (server, original_client) = Server::new(bind_address).unwrap();
        let cancel = CancellationToken::new();

        let server_handle = tokio::spawn(server.run(cancel.clone()));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let client1 = original_client.clone();
        let client2 = original_client.clone();
        let client3 = original_client.clone();

        let mut handles = Vec::new();

        for client in [client1, client2, client3].into_iter() {
            let handle = tokio::spawn(async move {
                send_multiple_metrics(&client, metrics::Msg::BlockReceived, 5);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        let metrics_url = create_endpoint_url(bind_address, "metrics");

        let response = reqwest::get(metrics_url).await.unwrap();
        let metrics_text = response.text().await.unwrap();
        assert!(metrics_text.contains("blocks_received_total 15"));

        cancel.cancel();
        _ = server_handle.await;
    }

    /// Helper function to create test configuration with OS-selected port
    fn localhost_with_random_port() -> Option<SocketAddrV4> {
        Some(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), random()))
    }

    fn create_endpoint_url(bind_address: Option<SocketAddrV4>, endpoint: &str) -> String {
        format!("http://{}/{endpoint}", bind_address.unwrap())
    }

    fn send_multiple_metrics(
        monitoring_client: &Client,
        msg: metrics::Msg,
        number_of_messages: usize,
    ) {
        for i in 0..number_of_messages {
            monitoring_client
                .metrics()
                .record_metric(msg.clone())
                .unwrap_or_else(|_| panic!("failed to send message {}", i));
        }
    }
}

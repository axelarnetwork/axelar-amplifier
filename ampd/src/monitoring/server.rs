use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use axum::routing::MethodRouter;
use axum::Router;
use error_stack::{Result, ResultExt};
use futures::future::join_all;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tokio::net::TcpListener;
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
    #[error("failed to check server bind address")]
    SocketAddr,
}

/// Configuration for the monitoring server
///
/// This enum ensures that the logical relationship between fields is maintained:
/// - When monitoring is disabled, no fields are required
/// - When monitoring is enabled, bind_address and channel_size are optional and will use sensible defaults if not specified
#[derive(Clone, PartialEq, Debug)]
pub enum Config {
    Disabled,
    Enabled {
        bind_address: SocketAddrV4,
        channel_size: usize,
    },
}

/// The default configuration of the monitoring server is disabled.
impl Default for Config {
    fn default() -> Self {
        Self::Disabled
    }
}

impl Config {
    /// Creates a new configuration with monitoring enabled using the default bind address
    ///
    /// The default bind address is `127.0.0.1:3000`.
    /// The default channel size is `1000`.
    pub fn enabled() -> Self {
        Self::Enabled {
            bind_address: default_bind_addr(),
            channel_size: default_channel_size(),
        }
    }
}

fn default_bind_addr() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000)
}

fn default_channel_size() -> usize {
    1000
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
            channel_size: usize,
        }

        let compat = match self {
            Config::Disabled => ConfigCompat {
                enabled: false,
                bind_address: default_bind_addr(),
                channel_size: default_channel_size(),
            },
            Config::Enabled {
                bind_address,
                channel_size,
            } => ConfigCompat {
                enabled: true,
                bind_address: *bind_address,
                channel_size: *channel_size,
            },
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
            #[serde(default = "default_bind_addr")]
            bind_address: SocketAddrV4,
            #[serde(default = "default_channel_size")]
            channel_size: usize,
        }

        let compat = ConfigCompat::deserialize(deserializer)?;

        Ok(if compat.enabled {
            Config::Enabled {
                bind_address: compat.bind_address,
                channel_size: compat.channel_size,
            }
        } else {
            Config::Disabled
        })
    }
}

/// Client for interacting with the monitoring system
///
/// Provides access to metrics collection and other monitoring functionality.
/// This client can be cloned and used across different parts of the application.
#[derive(Clone, Debug)]
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
    pub fn new(config: Config) -> Result<(Server, Client), Error> {
        match config {
            Config::Enabled {
                bind_address,
                channel_size,
            } => Self::create_server_with_client(TcpConnector::from(bind_address), channel_size),

            Config::Disabled => {
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

    fn create_server_with_client(
        tcp_connector: TcpConnector,
        channel_size: usize,
    ) -> Result<(Server, Client), Error> {
        let status_router = status::create_endpoint();
        let (metrics_router, metrics_process, metrics_client) =
            metrics::create_endpoint(channel_size);

        let server = Server::Enabled {
            server: HttpServer {
                tcp_connector,
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
            Server::Enabled { server } => server.serve(cancel).await,
        }
    }
}

/// TCP connection abstraction for the monitoring server
///
/// This enum allows the server to be configured with either a socket address
/// to bind to, or an existing TCP listener. This flexibility enables different
/// deployment scenarios, such as using OS-assigned ports or providing
/// pre-configured listeners.
///
/// # Variants
///
/// - `Address`: Contains a socket address that the server will bind to
/// - `Listener`: Contains an already-bound TCP listener ready for use
pub enum TcpConnector {
    Address(SocketAddr),
    Listener(TcpListener),
}

impl TcpConnector {
    /// Establishes a TCP connection, returning a bound listener
    ///
    /// For `Address` variants, this will bind to the specified socket address.
    /// For `Listener` variants, this returns the existing listener as-is.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if binding to the address fails (only applicable
    /// for `Address` variants).
    pub async fn connect(self) -> Result<TcpListener, Error> {
        match self {
            TcpConnector::Address(addr) => {
                TcpListener::bind(addr).await.change_context(Error::Start)
            }
            TcpConnector::Listener(listener) => Ok(listener),
        }
    }

    /// Returns the socket address this connector is bound to
    ///
    /// For `Address` variants, returns the configured address.
    /// For `Listener` variants, queries the listener for its local address.
    ///
    /// # Errors
    ///
    /// Returns an error if unable to determine the socket address from
    /// an existing listener.
    pub fn bind_address(&self) -> Result<SocketAddr, Error> {
        match self {
            TcpConnector::Address(addr) => Ok(*addr),
            TcpConnector::Listener(listener) => {
                listener.local_addr().change_context(Error::SocketAddr)
            }
        }
    }
}

impl From<SocketAddr> for TcpConnector {
    fn from(addr: SocketAddr) -> Self {
        TcpConnector::Address(addr)
    }
}

impl From<SocketAddrV4> for TcpConnector {
    fn from(addr: SocketAddrV4) -> Self {
        TcpConnector::Address(addr.into())
    }
}

impl From<TcpListener> for TcpConnector {
    fn from(listener: TcpListener) -> Self {
        TcpConnector::Listener(listener)
    }
}

/// HTTP server implementation for monitoring endpoints
///
/// This struct contains the actual HTTP server implementation that serves
/// monitoring endpoints like `/metrics` and `/status`.
pub struct HttpServer {
    routes: HashMap<&'static str, MethodRouter>,
    endpoint_handles: Vec<Box<dyn FnOnce(CancellationToken) -> JoinHandle<()> + Send>>,
    tcp_connector: TcpConnector,
}

impl HttpServer {
    async fn serve(self, cancel: CancellationToken) -> Result<(), Error> {
        info!(
            address = self.tcp_connector.bind_address()?.to_string(),
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

        let listener = self.tcp_connector.connect().await?;

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

    use tokio::test as async_test;
    use tracing_test::traced_test;

    use super::*;
    use crate::monitoring::endpoints::status::Status;
    use crate::monitoring::metrics::test_utils;

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
        env::set_var("TEST_MONITORING_CHANNEL_SIZE", "500");

        let enabled_config: Config = cfg::builder()
            .add_source(Environment::with_prefix("TEST_MONITORING"))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(
            enabled_config,
            Config::Enabled {
                bind_address: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 4000),
                channel_size: 500,
            }
        );

        // Test parsing disabled config from environment variable
        env::set_var("TEST_MONITORING_ENABLED", "false");
        let disabled_config: Config = cfg::builder()
            .add_source(Environment::with_prefix("TEST_MONITORING"))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(disabled_config, Config::Disabled);

        // Clean up
        env::remove_var("TEST_MONITORING_ENABLED");
        env::remove_var("TEST_MONITORING_BIND_ADDRESS");
        env::remove_var("TEST_MONITORING_CHANNEL_SIZE");
    }

    #[test]
    #[traced_test]
    fn disabled_client_discards_messages_without_error() {
        let (_, client) = Server::new(Config::Disabled).unwrap(); // Creates disabled server and client

        // Should succeed without doing anything
        client.metrics().record_metric(metrics::Msg::BlockReceived);
        assert!(
            !logs_contain("failed to record metrics"),
            "disabled client should discard messages successfully"
        );

        // Multiple messages should also work
        for _ in 0..100 {
            client.metrics().record_metric(metrics::Msg::BlockReceived);
            assert!(
                !logs_contain("failed to record metrics"),
                "disabled client should handle multiple messages"
            );
        }
    }

    #[async_test]
    async fn disabled_server_shuts_down_when_cancelled() {
        let (server, _) = Server::new(Config::Disabled).unwrap(); // Creates disabled server
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
        let listener = listener().await.connect().await.unwrap();
        let blocked_addr = convert_to_socketaddrv4(listener.local_addr().unwrap());

        // Create a server on the same address - creation should succeed
        let (server, _) = Server::new(Config::Enabled {
            bind_address: blocked_addr,
            channel_size: 1000,
        })
        .unwrap();

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
        let bind_address = listener().await.bind_address().unwrap();
        let channel_size = 1000;
        let status_url = create_endpoint_url(bind_address, "status");

        let (server, _) = Server::new(Config::Enabled {
            bind_address: convert_to_socketaddrv4(bind_address),
            channel_size,
        })
        .unwrap();
        let cancel = CancellationToken::new();

        let server_handle = tokio::spawn(server.run(cancel.clone()));

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
        let bind_address = listener().await.bind_address().unwrap();
        let channel_size = 1000;
        let metrics_url = create_endpoint_url(bind_address, "metrics");

        let (server, monitoring_client) = Server::new(Config::Enabled {
            bind_address: convert_to_socketaddrv4(bind_address),
            channel_size,
        })
        .unwrap();
        let cancel = CancellationToken::new();

        let server_handle = tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        send_multiple_metrics(&monitoring_client, metrics::Msg::BlockReceived, 3);
        drop(monitoring_client);

        tokio::time::sleep(Duration::from_millis(100)).await;

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
        let bind_address = listener().await.bind_address().unwrap();
        let channel_size = 1000;
        let metrics_url = create_endpoint_url(bind_address, "metrics");

        let (server, monitoring_client) = Server::new(Config::Enabled {
            bind_address: convert_to_socketaddrv4(bind_address),
            channel_size,
        })
        .unwrap();
        let cancel = CancellationToken::new();

        let server_handle = tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let initial_metrics = reqwest::get(metrics_url.clone()).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, initial_metrics.status());
        let initial_text = initial_metrics.text().await.unwrap();

        send_multiple_metrics(&monitoring_client, metrics::Msg::BlockReceived, 3);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let updated_metrics = reqwest::get(metrics_url).await.unwrap();
        let updated_text = updated_metrics.text().await.unwrap();

        let output = format!(
            "Initial Metrics:\n{}\n\nUpdated Metrics:\n{}",
            initial_text, updated_text
        );

        goldie::assert!(test_utils::zeroize_system_metrics(&output));
        cancel.cancel();
        _ = server_handle.await;
    }

    #[async_test(start_paused = true)]
    #[traced_test]
    async fn enabled_server_shuts_down_gracefully_when_cancellation_token_triggered() {
        let channel_size = 1000;
        let bind_address = convert_to_socketaddrv4(listener().await.bind_address().unwrap());
        let (server, monitoring_client) = Server::new(Config::Enabled {
            bind_address,
            channel_size,
        })
        .unwrap();
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
        monitoring_client
            .metrics()
            .record_metric(metrics::Msg::BlockReceived);

        assert!(
            logs_contain("failed to record metrics"),
            "client should not be able to send messages after server shutdown"
        );
    }

    #[async_test(start_paused = true)]
    async fn enabled_server_handles_concurrent_metrics_requests_correctly() {
        let bind_address = listener().await.bind_address().unwrap();
        let channel_size = 1000;
        let metrics_url = create_endpoint_url(bind_address, "metrics");

        let (server, original_client) = Server::new(Config::Enabled {
            bind_address: convert_to_socketaddrv4(bind_address),
            channel_size,
        })
        .unwrap();
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

        let response = reqwest::get(metrics_url).await.unwrap();
        let metrics_text = response.text().await.unwrap();
        assert!(metrics_text.contains("blocks_received_total 15"));

        cancel.cancel();
        _ = server_handle.await;
    }

    /// Helper function to create test configuration with OS-selected port.
    /// This helps to prevent port conflicts during tests.
    async fn listener() -> TcpConnector {
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0))
            .await
            .unwrap()
            .into()
    }

    fn create_endpoint_url(bind_address: SocketAddr, endpoint: &str) -> String {
        format!("http://{}/{endpoint}", bind_address)
    }

    fn convert_to_socketaddrv4(addr: SocketAddr) -> SocketAddrV4 {
        match addr {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => panic!("expected IPv4 address in this test"),
        }
    }

    fn send_multiple_metrics(
        monitoring_client: &Client,
        msg: metrics::Msg,
        number_of_messages: usize,
    ) {
        for _ in 0..number_of_messages {
            monitoring_client.metrics().record_metric(msg.clone());
        }
    }
}

#[cfg(test)]
pub mod test_utils {
    use tokio::sync::mpsc;

    use super::Client;
    use crate::monitoring::metrics::{Client as MetricsClient, Msg};

    pub fn monitoring_client() -> (Client, mpsc::Receiver<Msg>) {
        let (tx, rx) = mpsc::channel(10);
        let metrics_client = MetricsClient::WithChannel { sender: tx };
        let monitoring_client = Client { metrics_client };
        (monitoring_client, rx)
    }
}

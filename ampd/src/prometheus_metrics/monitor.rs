use std::net::SocketAddrV4;

use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use error_stack::{Result, ResultExt};
use prometheus::Registry;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::client::MetricsClient;
use crate::prometheus_metrics::metrics::Metrics;
use crate::prometheus_metrics::msg::{MetricsError, MetricsMsg};

const CHANNEL_SIZE: usize = 1000;

// we need to access the metrics server concurrently
// one for receiving metrics messages
// one for http requests ->  Arc to allow shared ownership
// Mutex to protect the metrics server from concurrent access
// lock() to ensure only one thread can access the metrics server at a time

pub struct Server {
    bind_address: Option<SocketAddrV4>,
    metrics_rx: mpsc::Receiver<MetricsMsg>,
}

// configured enables the server to run with or without metrics
impl Server {
    pub fn new(
        bind_address: Option<SocketAddrV4>,
    ) -> Result<(Self, crate::prometheus_metrics::client::MetricsClient), MetricsError> {
        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);

        let client = MetricsClient::new(tx);

        let server = Self {
            bind_address,
            metrics_rx: rx,
        };

        Ok((server, client))
    }

    pub async fn run(self, cancel: CancellationToken) -> Result<(), MetricsError> {
        if let Some(addr) = self.bind_address {
            Self::run_server(addr, self.metrics_rx, cancel).await
        } else {
            Self::run_dummy(self.metrics_rx, cancel).await;
            Ok(())
        }
    }

    async fn run_dummy(mut metrics_rx: mpsc::Receiver<MetricsMsg>, cancel: CancellationToken) {
        info!("running dummy server, no metrics will be collected");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // one branch for receiving messages from the metrics channel
                    msg = metrics_rx.recv() => {
                        match msg {
                            Some(_) =>{

                            }
                            None => {
                                    break;
                                }
                    }
                }

                    // another branch for graceful shutdown
                    _ = cancel.cancelled() => {
                        break;
                    }
                }
            }
        });
    }

    async fn run_server(
        addr: SocketAddrV4,
        metrics_rx: mpsc::Receiver<MetricsMsg>,
        cancel: CancellationToken,
    ) -> std::result::Result<(), error_stack::Report<MetricsError>> {
        let registry = prometheus::Registry::new();
        let metrics = Metrics::new(&registry)?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .change_context(MetricsError::Start)?;

        info!(address = addr.to_string(), "starting monitor server");

        Self::start_metrics_processing(metrics, metrics_rx, cancel.clone());

        // host the metrics routes, if not available, return 404
        let app = Router::new().route("/status", get(status)).route(
            "/metrics",
            get(move || async move { gather_metrics(&registry).await }),
        );

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                cancel.cancelled().await;
                info!("exiting monitor server")
            })
            .await
            .change_context(MetricsError::WhileRunning)?;
        Ok(())
    }

    // error handling ideas
    //
    fn start_metrics_processing(
        server: Metrics,
        mut metrics_rx: mpsc::Receiver<MetricsMsg>,
        cancel: CancellationToken,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // one branch for receiving messages from the metrics channel
                    msg = metrics_rx.recv() => {
                        match msg {
                            Some(msg) => {
                                if let Err(e) = server.handle_message(msg) {
                                    tracing::error!("Failed to handle metrics message: {:?}", e);
                                }
                            }
                            None => {
                                // channel closed, exit the loop
                                break;
                            }
                        }
                    }
                    // another branch for graceful shutdown
                    _ = cancel.cancelled() => {
                        break;
                    }
                }
            }
        });
    }
}

// basic handler that responds with a static string
async fn status() -> (StatusCode, Json<Status>) {
    (StatusCode::OK, Json(Status { ok: true }))
}

async fn gather_metrics(registry: &Registry) -> (StatusCode, String) {
    match crate::prometheus_metrics::metrics::gather(registry) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to gather metrics: {}", e),
        ),
    }
}

#[derive(Serialize, Deserialize)]
struct Status {
    ok: bool,
}

#[cfg(test)]
mod tests {

    use std::net::{SocketAddr, TcpListener};
    use std::time::Duration;

    use tokio::test as async_test;

    use super::*;

    #[async_test]
    async fn server_lifecycle() {
        let bind_address = test_bind_addr();

        let (server, _metrics_client) = Server::new(bind_address).expect("Failed to create server");

        let cancel = CancellationToken::new();

        tokio::spawn(server.run(cancel.clone()));

        let url = format!("http://{}/status", bind_address.unwrap());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let response = reqwest::get(&url).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, response.status());

        let status = response.json::<Status>().await.unwrap();
        assert!(status.ok);

        cancel.cancel();

        tokio::time::sleep(Duration::from_millis(100)).await;

        match reqwest::get(&url).await {
            Ok(_) => panic!("monitor server should be closed by now"),
            Err(error) => assert!(error.is_connect()),
        };
    }

    fn test_bind_addr() -> Option<SocketAddrV4> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        match listener.local_addr().unwrap() {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => panic!("unexpected address"),
        }
    }

    #[async_test]
    async fn server_with_metrics() {
        let bind_address = test_bind_addr();
        let (server, metrics_client) =
            Server::new(bind_address).expect("Failed to create server with metrics");

        let cancel = CancellationToken::new();

        tokio::spawn(server.run(cancel.clone()));
        let status_url = format!("http://{}/status", bind_address.unwrap());
        let metrics_url = format!("http://{}/metrics", bind_address.unwrap());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let status_response = reqwest::get(&status_url).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, status_response.status());

        let initial_metrics = reqwest::get(&metrics_url).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, initial_metrics.status());
        let initial_text = initial_metrics.text().await.unwrap();

        assert!(
            initial_text.contains("blocks_received 0"),
            "got: {}, should be 0 ",
            initial_text
        );

        let mut handles = vec![];

        for i in 0..3 {
            let client_clone = metrics_client.clone();
            let handle = tokio::spawn(async move {
                client_clone
                    .send_metrics_msg(MetricsMsg::IncBlockReceived)
                    .unwrap_or_else(|_| panic!("Task {} failed to increase block counter", i));
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.expect("Task failed");
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        let updated_metrics = reqwest::get(&metrics_url).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, updated_metrics.status());
        let updated_text = updated_metrics.text().await.unwrap();

        assert!(
            updated_text.contains("blocks_received 3"),
            "got {} block, should be 3",
            updated_text
        );

        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;

        match reqwest::get(&metrics_url).await {
            Ok(_) => panic!("metrics server should be closed"),
            Err(error) => assert!(error.is_connect()),
        };
    }

    #[async_test]
    async fn metrics_task_graceful_shutdown_with_client() {
        let bind_address = test_bind_addr();
        let (server, metrics_client) =
            Server::new(bind_address).expect("Failed to create server with metrics");

        let cancel = CancellationToken::new();
        let server_handle = tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        // send some metrics messages to the server
        for i in 0..3 {
            metrics_client
                .send_metrics_msg(MetricsMsg::IncBlockReceived)
                .unwrap_or_else(|_| panic!("Failed to send block received {}", i));
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify metrics are correctly updated
        let metrics_url = format!("http://{}/metrics", bind_address.unwrap());
        let response = reqwest::get(&metrics_url).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, response.status());
        let metrics_text = response.text().await.unwrap();

        assert!(
            metrics_text.contains("blocks_received 3"),
            "Expected blocks_received 3, got: {}",
            metrics_text
        );

        println!("Cancelling server...");
        cancel.cancel();

        let shutdown_result = tokio::time::timeout(Duration::from_secs(2), server_handle).await;

        assert!(
            shutdown_result.is_ok(),
            "Server should have shut down gracefully within 2 seconds"
        );

        let server_result = shutdown_result.unwrap();
        assert!(
            server_result.is_ok(),
            "Server should have completed without errors: {:?}",
            server_result
        );
        // Verify server is actually down
        tokio::time::sleep(Duration::from_millis(100)).await;
        match reqwest::get(&metrics_url).await {
            Ok(_) => panic!("Server should be shut down and not accepting connections"),
            Err(error) => {
                assert!(
                    error.is_connect(),
                    "Expected connection error, got: {:?}",
                    error
                );
                println!("Server correctly shut down - connection refused");
            }
        }
    }
}

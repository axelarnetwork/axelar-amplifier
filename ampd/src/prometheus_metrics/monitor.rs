use std::net::SocketAddrV4;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use error_stack::{Result, ResultExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::client::MetricsClient;
use crate::prometheus_metrics::msg::{MetricsError, MetricsMsg};
use crate::prometheus_metrics::server::MetricsServer;

const CHANNEL_SIZE: usize = 1000;

// we need to access the metrics server concurrently
// one for receiving metrics messages
// one for http requests ->  Arc to allow shared ownership
// Mutex to protect the metrics server from concurrent access
// lock() to ensure only one thread can access the metrics server at a time

pub struct Server {
    bind_address: SocketAddrV4,
    metrics_server: Option<Arc<Mutex<MetricsServer>>>,
    metrics_rx: Option<mpsc::Receiver<MetricsMsg>>,
}

// configured enables the server to run with or without metrics
impl Server {
    pub fn new(
        bind_address: SocketAddrV4,
        configured: bool, // ← Add configuration parameter
    ) -> Result<
        (
            Self,
            Option<crate::prometheus_metrics::client::MetricsClient>,
        ),
        MetricsError,
    > {
        if !configured {
            // return a server without metrics
            let server = Self {
                bind_address,
                metrics_server: None,
                metrics_rx: None,
            };
            return Ok((server, None));
        }

        // Create metrics
        let server = MetricsServer::new()?;
        let shared_server = Arc::new(Mutex::new(server));
        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);
        let client = MetricsClient::new(tx);

        let server = Self {
            bind_address,
            metrics_server: Some(shared_server),
            metrics_rx: Some(rx),
        };

        Ok((server, Some(client)))
    }

    pub async fn run(mut self, cancel: CancellationToken) -> Result<(), MetricsError> {
        let listener = tokio::net::TcpListener::bind(self.bind_address)
            .await
            .change_context(MetricsError::Start)?;

        info!(
            address = self.bind_address.to_string(),
            "starting monitor server"
        );

        // Start metrics processing if available
        if let (Some(metrics_server), Some(metrics_rx)) =
            (self.metrics_server.clone(), self.metrics_rx.take())
        {
            Self::start_metrics_processing(metrics_server, metrics_rx, cancel.clone());
        }
        // host the metrics routes, if not available, return 404
        let app = Router::new().route("/status", get(status)).route(
            "/metrics",
            get({
                let metrics_server = self.metrics_server.clone();
                move || async move {
                    if let Some(server) = metrics_server {
                        metrics(server).await
                    } else {
                        (StatusCode::NOT_FOUND, "Metrics not available".to_string())
                    }
                }
            }),
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
        metrics_server: Arc<Mutex<MetricsServer>>,
        mut metrics_rx: mpsc::Receiver<MetricsMsg>,
        cancel: CancellationToken,
    ) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // one branch for receiving messages from the metrics channel
                    msg = metrics_rx.recv() => {
                        match msg {
                            Some(msg) => {
                                let mut server_guard = metrics_server.lock().await;
                                if let Err(e) = server_guard.handle_message(msg) {
                                    tracing::error!("Failed to handle metrics message: {:?}", e);
                                }
                            }
                            None => {
                                // channel closed, exit the loop
                                break;
                            }
                        }
                    }
                    // another branch for periodic metrics gathering ! for Proof of concept !
                    _ = interval.tick() => {
                        let server_guard = metrics_server.lock().await;
                        match server_guard.gather() {
                            Ok(metrics) => {
                                tracing::info!("Metrics: {}", metrics); // log
                            }
                            Err(e) => {
                                tracing::error!("Failed to gather metrics: {:?}", e);
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

async fn metrics(metrics_server: Arc<Mutex<MetricsServer>>) -> (StatusCode, String) {
    let server = metrics_server.lock().await;
    match server.gather() {
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

        let (server, _metrics_client) =
            Server::new(bind_address, false).expect("Failed to create server");

        let cancel = CancellationToken::new();

        tokio::spawn(server.run(cancel.clone()));

        let url = format!("http://{}/status", bind_address);

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

    fn test_bind_addr() -> SocketAddrV4 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        match listener.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("unexpected address"),
        }
    }
    #[async_test]
    async fn server_with_metrics() {
        let bind_address = test_bind_addr();
        let (server, metrics_client) =
            Server::new(bind_address, true).expect("Failed to create server with metrics");

        let cancel = CancellationToken::new();

        tokio::spawn(server.run(cancel.clone()));
        let status_url = format!("http://{}/status", bind_address);
        let metrics_url = format!("http://{}/metrics", bind_address);

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
                if let Some(client1) = client_clone {
                    client1
                        .inc_block_received()
                        .unwrap_or_else(|_| panic!("Task {} failed to increase block counter", i));
                } else {
                    panic!("MetricsClient is None");
                }
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
            Server::new(bind_address, true).expect("Failed to create server with metrics");

        let cancel = CancellationToken::new();
        let server_handle = tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        // send some metrics messages to the server
        if let Some(ref client) = metrics_client {
            for i in 0..3 {
                client
                    .inc_block_received()
                    .unwrap_or_else(|_| panic!("Failed to send block received {}", i));
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify metrics are correctly updated
        let metrics_url = format!("http://{}/metrics", bind_address);
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

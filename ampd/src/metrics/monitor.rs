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
use crate::metrics::msg::MetricsError;
use crate::metrics::server::MetricsServer;
use crate::metrics::msg::MetricsMsg;

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
// field: metricsServer: T/F

impl Server {
    pub fn new(
        bind_address: SocketAddrV4,
    ) -> Result<(Self, Option<crate::metrics::client::MetricsClient>), MetricsError> {
        // log a warning if failed to initailized , server and metrics tx will be None 
        let (metrics_server, metrics_rx, client) = match MetricsServer::new() {
            Ok(server) => {
                let shared_server = Arc::new(Mutex::new(server));
                let (tx, rx) = mpsc::channel(1000);
                let client = Some(MetricsClient::new(tx));
                (Some(shared_server), Some(rx), client)
            }
            Err(e) => {
                tracing::warn!("Failed to initialize metrics server: {:?}", e);
                (None, None, None) 
            }
        };

        let server = Self {
            bind_address,
            metrics_server,
            metrics_rx,
        };
        Ok((server, client))
    }



    pub async fn run(self, cancel: CancellationToken) -> Result<(), MetricsError> {
        let listener = tokio::net::TcpListener::bind(self.bind_address)
            .await
            .change_context(MetricsError::Start)?;

        info!(
            address = self.bind_address.to_string(),
            "starting monitor server"
        );
        // receive messages from the metrics channel -> always 
        if let (Some(metrics_server), Some(mut metrics_rx)) = (self.metrics_server.clone(), self.metrics_rx) {
            tokio::spawn(async move {
                while let Some(msg) = metrics_rx.recv().await {
                    let mut server_guard = metrics_server.lock().await;
                    if let Err(e) = server_guard.handle_message(msg) {
                        tracing::error!("Failed to handle metrics message: {:?}", e);
                    }
                }
            });
        }

        let app = Router::new()
        .route("/status", get(status))
        .route(
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
            Server::new(bind_address).expect("Failed to create server and metrics client");

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
            Server::new(bind_address).expect("Failed to create server with metrics");

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
                        .expect(&format!("Task {} failed to increase block counter", i));
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
}

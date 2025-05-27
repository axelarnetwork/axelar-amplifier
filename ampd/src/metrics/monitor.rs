use std::net::SocketAddrV4;
use std::sync::Arc; 
use tokio::sync::Mutex;
use error_stack::{Result, ResultExt}; 
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::mpsc;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::info;


use crate::metrics::msg::MetricsError;
use crate::metrics::server::MetricsServer;

use super::client::MetricsClient;

// we need to access the metrics server concurrently 
// one for receiving metrics messages
// one for http requests ->  Arc to allow shared ownership 
// Mutex to protect the metrics server from concurrent access
// lock() to ensure only one thread can access the metrics server at a time
pub struct Server {
    bind_address: SocketAddrV4,
    metrics_server: Arc<Mutex<MetricsServer>>, 
}

impl Server {
    pub fn new(
        bind_address: SocketAddrV4,
    ) -> Result<(Self, crate::metrics::client::MetricsClient), MetricsError> {
        let (tx, mut rx) = mpsc::channel(1000); 
        let metrics_server_logic = MetricsServer::new()
            .change_context(MetricsError::Start)?;
        let shared_metrics_server = Arc::new(Mutex::new(metrics_server_logic));
        let client = MetricsClient::new(tx);

        let processor_metrics_server_arc = shared_metrics_server.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let mut server_guard = processor_metrics_server_arc.lock().await;
                server_guard.handle_message(msg)?;
            }
            Ok::<_, MetricsError>(())
        });

        Ok((
            Self {
                bind_address,
                metrics_server: shared_metrics_server,
            },
            client,
        ))
    }

    pub async fn run(self, cancel: CancellationToken) -> Result<(), MetricsError> {
        let listener = tokio::net::TcpListener::bind(self.bind_address)
            .await
            .change_context(MetricsError::Start)?;

        info!(
            address = self.bind_address.to_string(),
            "starting monitor server"
        );
       

        let app = Router::new()
            .route("/status", get(status))
            .route("/metrics", get(move || metrics(self.metrics_server.clone())));

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
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to gather metrics: {}", e)),
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
                client_clone
                    .inc_block_received()
                    .expect(&format!("Task {} failed to increase block counter", i));
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

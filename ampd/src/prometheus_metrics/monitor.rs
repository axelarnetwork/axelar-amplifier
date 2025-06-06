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
use crate::prometheus_metrics::metrics::{self, Metrics};
use crate::prometheus_metrics::msg::{MetricsError, MetricsMsg};
use reqwest::Url;


// safe upper bound for expected metric throughput;
// shouldnt exceed 1000 message currently 
const CHANNEL_SIZE: usize = 1000;

pub struct Server {
    bind_address: Option<SocketAddrV4>,
    metrics_rx: mpsc::Receiver<MetricsMsg>,
}

impl Server {
    pub fn new(bind_address: Option<SocketAddrV4>) -> Result<(Self, MetricsClient), MetricsError> {
        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);

        let client = MetricsClient::new(tx);

        let server = Self {
            bind_address,
            metrics_rx: rx,
        };

        Ok((server, client))
    }

    pub async fn run(self, cancel: CancellationToken) -> Result<(), MetricsError> {
        match self.bind_address {
            Some(addr) => Self::run_server(addr, self.metrics_rx, cancel).await,
            None => Self::run_dummy(self.metrics_rx, cancel).await
        }
    }

    async fn run_dummy(mut metrics_rx: mpsc::Receiver<MetricsMsg>, cancel: CancellationToken) -> Result<(), MetricsError> {
        info!("no prometheus endpoint defined, so no metrics will be collected");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = metrics_rx.recv() => {
                        match msg {
                            Some(_) =>{}
                            None => break,
                        }
                    }
                    _ = cancel.cancelled() => {
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    async fn run_server(
        addr: SocketAddrV4,
        metrics_rx: mpsc::Receiver<MetricsMsg>,
        cancel: CancellationToken,
    ) -> Result<(), MetricsError> {
        let registry = prometheus::Registry::new();
        let metrics = Metrics::new(&registry)?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .change_context(MetricsError::Start)?;

        info!(address = addr.to_string(), "starting monitoring server");

        let metrics_handle = Self::start_metrics_processing(metrics, metrics_rx, cancel.clone());

        // host the metrics routes, if not available, return 404
        let app = Router::new().route("/status", get(status)).route(
            "/metrics",
            get(move || async move { gather_metrics(&registry).await }),
        );

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                cancel.cancelled().await;
                info!("shutting down monitoring server")
            })
            .await
            .change_context(MetricsError::WhileRunning)?;
        let _ = metrics_handle.await;
        Ok(())
        // handle joinHanlde? 
    }

    fn start_metrics_processing(
        server: Metrics,
        mut metrics_rx: mpsc::Receiver<MetricsMsg>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = metrics_rx.recv() => {
                        match msg {
                            Some(msg) => {
                                server.handle_message(msg) 
                            }
                            None => break
                        }
                    }
                    _ = cancel.cancelled() => break
                    
                }
            }
        })
    }
}

async fn status() -> (StatusCode, Json<Status>) {
    (StatusCode::OK, Json(Status { ok: true }))
}

async fn gather_metrics(registry: &Registry) -> (StatusCode, String) {
    match metrics::gather(registry) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            e.to_string(),
        ),
    }
}

#[derive(Serialize, Deserialize)]
struct Status {
    ok: bool,
}

#[cfg(test)]
pub mod tests {
    use std::net::{SocketAddr, TcpListener};
    use std::time::Duration;

    use tokio::test as async_test;
    use super::*;

    pub fn test_bind_addr() -> Option<SocketAddrV4> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        match listener.local_addr().unwrap() {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => panic!("unexpected address"),
        }
    }

    #[async_test(start_paused = true)] 
    async fn server_starts_responds_to_status_and_shuts_down_gracefully()  {
    fn test_bind_addr() -> Option<SocketAddrV4> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        match listener.local_addr().unwrap() {
            SocketAddr::V4(addr) => Some(addr),
            SocketAddr::V6(_) => panic!("unexpected address"),
        }
    }

    pub fn test_server_setup() -> (
        Option<SocketAddrV4>,
        Server,
        MetricsClient,
        CancellationToken,
    ) {
        let bind_address = test_bind_addr();
        let (server, metrics_client) = Server::new(bind_address).expect("Failed to create server");
        let cancel = CancellationToken::new();

        let (server, _metrics_client) = Server::new(bind_address).expect("failed to create server");
        (bind_address, server, metrics_client, cancel)
    }

    pub fn test_dummy_server_setup() -> (Server, MetricsClient, CancellationToken) {
        let (server, metrics_client) = Server::new(None).expect("Failed to create server");
        let cancel = CancellationToken::new();

        (server, metrics_client, cancel)
    }

    fn send_metrics_client_msg(
        metrics_client: &MetricsClient,
        msg: MetricsMsg,
        number_of_messages: usize,
    ) {
        for i in 0..number_of_messages {
            metrics_client
                .send_metrics_msg(msg.clone())
                .unwrap_or_else(|_| panic!("Failed to send message {}", i));
        }
    }

    #[async_test]
    async fn server_lifecycle() {
        let (bind_address, server, _metrics_client, cancel) = test_server_setup();

        tokio::spawn(server.run(cancel.clone()));

        let base_url = Url::parse(&format!("http://{}", bind_address.unwrap())).unwrap();
        let url = base_url.join("status").unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let response = reqwest::get(url.clone()).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, response.status());

        let status = response.json::<Status>().await.unwrap();
        assert!(status.ok);

        cancel.cancel();

        tokio::time::sleep(Duration::from_millis(100)).await;

        match reqwest::get(url).await {
            Ok(_) => panic!("monitor server should be closed by now"),
            Err(error) => assert!(error.is_connect()),
        };
    }

    #[async_test]
    async fn metrics_collection_and_endpoints() {
        let (bind_address, server, metrics_client, cancel) = test_server_setup();

        tokio::spawn(server.run(cancel.clone()));
        let base_url = Url::parse(&format!("http://{}", bind_address.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let initial_metrics = reqwest::get(metrics_url.clone()).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, initial_metrics.status());
        let initial_text = initial_metrics.text().await.unwrap();
        assert!(initial_text.contains("blocks_received 0"));

        send_metrics_client_msg(&metrics_client, MetricsMsg::IncBlockReceived, 3);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let updated_metrics = reqwest::get(metrics_url).await.unwrap();
        let updated_text = updated_metrics.text().await.unwrap();
        assert!(updated_text.contains("blocks_received 3"));
        cancel.cancel();
    }

    #[async_test]
    async fn graceful_shutdown_with_handle() {
        let (_, server, metrics_client, cancel) = test_server_setup();

        let server_handle = tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        send_metrics_client_msg(&metrics_client, MetricsMsg::IncBlockReceived, 2);

        cancel.cancel();
        let shutdown_result = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
        assert!(
            shutdown_result.is_ok(),
            "server should shut down gracefully"
        );
        assert!(
            shutdown_result.unwrap().is_ok(),
            "server should complete without errors"
        );
    }

    #[async_test]
    async fn dummy_server_drop_client() {
        let (server, metrics_client, cancel) = test_dummy_server_setup();

        let server_handle = tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(50)).await;

        send_metrics_client_msg(&metrics_client, MetricsMsg::IncBlockReceived, 5);

        tokio::time::sleep(Duration::from_millis(50)).await;

        drop(metrics_client);

        let shutdown_result = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
        assert!(
            shutdown_result.is_ok(),
            "dummy server should exit when client is dropped"
        );
        assert!(
            shutdown_result.unwrap().is_ok(),
            "dummy server should complete without errors"
        );
    }

    #[async_test, start_paused = true]
    async fn concurrent_clients() {
        let (bind_address, server, original_client, cancel) = test_server_setup();

        tokio::spawn(server.run(cancel.clone()));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let client1 = original_client.clone();
        let client2 = original_client.clone();
        let client3 = original_client.clone();

        let mut handles = Vec::new();

        for client in [client1, client2, client3].into_iter() {
            let handle = tokio::spawn(async move {
                send_metrics_client_msg(&client, MetricsMsg::IncBlockReceived, 5);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await; 

        let base_url = Url::parse(&format!("http://{}", bind_address.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();
       
        let response = reqwest::get(metrics_url).await.unwrap();
        let metrics_text = response.text().await.unwrap();
        assert!(metrics_text.contains("blocks_received 15"));

        cancel.cancel();
    }
}

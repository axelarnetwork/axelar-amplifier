use std::net::SocketAddrV4;

use axum::routing::get;
use axum::Router;
use error_stack::{Result, ResultExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::monitoring::endpoints::metrics::{gather_metrics, Metrics, MetricsError};
use crate::monitoring::endpoints::status::status;
use crate::monitoring::MetricsMsg;

// safe upper bound for expected metric throughput;
// shouldnt exceed 1000 message
const CHANNEL_SIZE: usize = 1000;

#[derive(Clone)]
pub struct MetricsClient {
    sender: mpsc::Sender<MetricsMsg>,
}

impl MetricsClient {
    fn new(sender: mpsc::Sender<MetricsMsg>) -> Self {
        Self { sender }
    }

    pub fn record_metric(&self, msg: MetricsMsg) -> Result<(), MetricsError> {
        self.sender
            .try_send(msg)
            .change_context(MetricsError::MetricUpdateFailed)?;
        Ok(())
    }
}

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
            None => Self::run_dummy(self.metrics_rx, cancel).await,
        }
    }

    async fn run_dummy(
        mut metrics_rx: mpsc::Receiver<MetricsMsg>,
        cancel: CancellationToken,
    ) -> Result<(), MetricsError> {
        info!("no prometheus endpoint defined, so no metrics will be collected");

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = metrics_rx.recv() => {
                        match msg {
                            Some(_) =>{}
                            None => {
                                warn!("all metrics clients disconnected, metrics processing stopped");
                                break;
                            },
                        }
                    }
                    _ = cancel.cancelled() => break
                }
            }
        });
        _ = handle.await;
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
                            None => {
                                warn!("all metrics clients disconnected, metrics processing stopped");
                                break;
                            }
                        }
                    }
                    _ = cancel.cancelled() => break

                }
            }
        })
    }
}

#[cfg(test)]
pub mod test_utils {
    use std::net::{SocketAddr, TcpListener};

    use tokio_util::sync::CancellationToken;

    use super::*;

    fn test_bind_addr() -> SocketAddrV4 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();

        match listener.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("unexpected address"),
        }
    }

    pub fn test_metrics_server_setup() -> (
        Option<SocketAddrV4>,
        Server,
        MetricsClient,
        CancellationToken,
    ) {
        let bind_address = test_bind_addr();
        let (server, metrics_client) =
            Server::new(Some(bind_address)).expect("failed to create server");
        let cancel = CancellationToken::new();
        (Some(bind_address), server, metrics_client, cancel)
    }

    pub fn test_dummy_server_setup() -> (Server, MetricsClient, CancellationToken) {
        let (server, metrics_client) = Server::new(None).expect("failed to create server");
        let cancel = CancellationToken::new();
        (server, metrics_client, cancel)
    }

    pub fn send_mutiple_metrics(
        metrics_client: &MetricsClient,
        msg: MetricsMsg,
        number_of_messages: usize,
    ) {
        for i in 0..number_of_messages {
            metrics_client
                .record_metric(msg.clone())
                .unwrap_or_else(|_| panic!("failed to send message {}", i));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use reqwest::Url;
    use tokio::test as async_test;

    use super::test_utils::*;
    use super::*;
    use crate::monitoring::endpoints::status::Status;

    #[async_test(start_paused = true)]
    async fn metrics_server_should_respond_to_status_and_shutdown_gracefully() {
        let (bind_address, server, _metrics_client, cancel) = test_metrics_server_setup();

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

    #[async_test(start_paused = true)]
    async fn test_metrics_server_handles_all_clients_dropped() {
        let (bind_address, server, metrics_client, cancel) = test_metrics_server_setup();
        tokio::spawn(server.run(cancel.clone()));
        send_mutiple_metrics(&metrics_client, MetricsMsg::IncBlockReceived, 3);
        drop(metrics_client);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let base_url = Url::parse(&format!("http://{}", bind_address.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();
        let response = reqwest::get(metrics_url.clone()).await;
        assert!(
            response.is_ok(),
            "metrics server still running after client dropped"
        );
        cancel.cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;
        match reqwest::get(metrics_url).await {
            Ok(_) => panic!("monitor server should be closed by now"),
            Err(error) => assert!(error.is_connect()),
        };
    }

    #[async_test(start_paused = true)]
    async fn metrics_endpoint_should_reflect_message_counts() {
        let (bind_address, server, metrics_client, cancel) = test_metrics_server_setup();

        tokio::spawn(server.run(cancel.clone()));
        let base_url = Url::parse(&format!("http://{}", bind_address.unwrap())).unwrap();
        let metrics_url = base_url.join("metrics").unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let initial_metrics = reqwest::get(metrics_url.clone()).await.unwrap();
        assert_eq!(reqwest::StatusCode::OK, initial_metrics.status());
        let initial_text = initial_metrics.text().await.unwrap();
        assert!(initial_text.contains("blocks_received 0"));

        send_mutiple_metrics(&metrics_client, MetricsMsg::IncBlockReceived, 3);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let updated_metrics = reqwest::get(metrics_url).await.unwrap();
        let updated_text = updated_metrics.text().await.unwrap();
        assert!(updated_text.contains("blocks_received 3"));
        cancel.cancel();
    }

    #[async_test(start_paused = true)]
    async fn server_shuts_down_gracefully_when_token_is_cancelled() {
        let (_, server, metrics_client, cancel) = test_metrics_server_setup();

        let server_handle = tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        send_mutiple_metrics(&metrics_client, MetricsMsg::IncBlockReceived, 2);

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
        tokio::time::sleep(Duration::from_millis(100)).await;
        // client should not be able to send message after server shutdown
        let send_result = metrics_client.record_metric(MetricsMsg::IncBlockReceived);
        assert!(
            send_result.is_err(),
            "client should not be able to send messages after server shutdown"
        );
    }

    #[async_test(start_paused = true)]
    async fn dummy_server_exits_when_all_clients_are_dropped() {
        let (server, metrics_client, cancel) = test_dummy_server_setup();

        let server_handle = tokio::spawn(server.run(cancel.clone()));

        tokio::time::sleep(Duration::from_millis(50)).await;

        send_mutiple_metrics(&metrics_client, MetricsMsg::IncBlockReceived, 5);

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

    #[async_test(start_paused = true)]
    async fn dummy_server_client_fails_after_cancellation() {
        let (server, metrics_client, cancel) = test_dummy_server_setup();
        let server_handle = tokio::spawn(server.run(cancel.clone()));
        tokio::time::sleep(Duration::from_millis(50)).await;
        send_mutiple_metrics(&metrics_client, MetricsMsg::IncBlockReceived, 1);
        cancel.cancel();
        let shutdown_result = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
        assert!(
            shutdown_result.is_ok(),
            "dummy server should shut down gracefully when cancelled"
        );
        assert!(
            shutdown_result.unwrap().is_ok(),
            "dummy server should complete without errors"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let send_result = metrics_client.record_metric(MetricsMsg::IncBlockReceived);
        assert!(
            send_result.is_err(),
            "client should not be able to send messages after dummy server cancellation"
        );
    }

    #[async_test(start_paused = true)]
    async fn metrics_server_handle_concurrent_requests_sucessfully() {
        let (bind_address, server, original_client, cancel) = test_metrics_server_setup();

        tokio::spawn(server.run(cancel.clone()));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let client1 = original_client.clone();
        let client2 = original_client.clone();
        let client3 = original_client.clone();

        let mut handles = Vec::new();

        for client in [client1, client2, client3].into_iter() {
            let handle = tokio::spawn(async move {
                send_mutiple_metrics(&client, MetricsMsg::IncBlockReceived, 5);
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

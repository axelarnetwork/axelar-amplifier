use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, MethodRouter};
use error_stack::{Result, ResultExt};
use futures::StreamExt;
use prometheus::{Encoder, IntCounter, Registry, TextEncoder};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::log::warn;

// safe upper bound for expected metric throughput;
// shouldn't exceed 1000 message
const CHANNEL_SIZE: usize = 1000;

/// Messages for metrics collection
///
/// These messages are sent to the metrics processor to update various counters
/// and gauges tracked by the monitoring system.
#[derive(Clone)]
pub enum Msg {
    /// Increment the count of blocks received
    IncBlockReceived,
}

/// Errors that can occur in metrics processing
#[derive(Debug, Error)]
pub enum Error {
    /// UTF-8 conversion error when formatting metrics
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    /// Prometheus library error
    #[error(transparent)]
    Prometheus(#[from] prometheus::Error),
    /// Failed to update metric (e.g., channel full or closed)
    #[error("failed to update metric")]
    MetricUpdateFailed,
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

/// Client for sending metrics messages
///
/// This client is used throughout the application to record metrics events.
/// It can operate in two modes: with a real channel to a metrics processor,
/// or in disabled mode where messages are discarded.
#[derive(Clone)]
pub enum Client {
    /// Active client with a channel to send metrics messages
    WithChannel { sender: mpsc::Sender<Msg> },
    /// Disabled client that discards all metrics messages
    Disabled,
}

impl Client {
    /// Records a metric by sending a message to the metrics processor
    ///
    /// # Arguments
    ///
    /// * `msg` - The metrics message to record
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the metric was successfully recorded, or an error
    /// if the metrics processor is unavailable or the channel is full.
    ///
    /// # Behavior
    ///
    /// - For `Disabled` clients: Always succeeds without doing anything
    /// - For `WithChannel` clients: Attempts to send the message via channel
    pub fn record_metric(&self, msg: Msg) -> Result<(), Error> {
        match self {
            Client::Disabled => Ok(()),
            Client::WithChannel { sender } => sender
                .try_send(msg)
                .change_context(Error::MetricUpdateFailed),
        }
    }
}

/// Creates a metrics endpoint with processor and client
///
/// This function sets up the complete metrics infrastructure:
/// - HTTP endpoint for serving Prometheus metrics
/// - Background processor for handling metric updates
/// - Client for sending metric messages
///
/// # Returns
///
/// A tuple containing:
/// - `MethodRouter`: HTTP route handler for the `/metrics` endpoint
/// - `Process`: Background processor that handles metric updates
/// - `Client`: Client for recording metrics throughout the application
///
/// # Panics
///
/// Panics if the Prometheus registry cannot be created or
/// if metrics cannot be registered. This should never happen in normal operation.
pub fn create_endpoint() -> (MethodRouter, Process, Client) {
    let (tx, rx) = mpsc::channel(CHANNEL_SIZE);

    let registry = Registry::new();
    let metrics = Metrics::new(&registry);

    (
        get(|| async { serve_metrics(registry) }),
        Process::new(rx, metrics),
        Client::WithChannel { sender: tx },
    )
}

/// Background processor for handling metrics messages
///
/// This processor runs in a separate task and updates metrics based on
/// messages received from clients throughout the application.
pub struct Process {
    stream: ReceiverStream<Msg>,
    metrics: Metrics,
}

impl Process {
    /// Creates a new metrics processor
    fn new(metrics_rx: mpsc::Receiver<Msg>, metrics: Metrics) -> Self {
        Self {
            stream: ReceiverStream::new(metrics_rx),
            metrics,
        }
    }

    /// Runs the metrics processor until cancellation or all clients disconnect
    ///
    /// # Arguments
    ///
    /// * `cancel` - Cancellation token to stop the processor
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the spawned processing task
    ///
    /// # Behavior
    ///
    /// The processor will continue running until either:
    /// - The cancellation token is triggered
    /// - All metrics clients are dropped and the channel closes
    ///
    /// When all clients are dropped, a warning is logged.
    pub fn run(self, cancel: CancellationToken) -> JoinHandle<()> {
        tokio::spawn(async move {
            let stream = self.stream.take_until(cancel.cancelled());

            tokio::pin!(stream);
            while let Some(msg) = stream.next().await {
                self.metrics.handle_message(msg);
            }

            if !cancel.is_cancelled() {
                warn!("all metrics clients disconnected, metrics processing stopped");
            }
        })
    }
}

fn serve_metrics(registry: Registry) -> core::result::Result<String, Error> {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();

    encoder.encode(&metric_families, &mut buffer)?;

    Ok(String::from_utf8(buffer)?)
}

struct Metrics {
    block_received: IntCounter,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        // all created metrics are static, so errors during registration are bugs and should panic
        let block_received = IntCounter::new("blocks_received", "number of blocks received")
            .expect("failed to create blocks_received counter");

        registry.register(Box::new(block_received.clone()))
            .expect("failed to register blocks_received counter");

        Self { block_received }
    }

    pub fn handle_message(&self, msg: Msg) {
        match msg {
            Msg::IncBlockReceived => {
                self.block_received.inc();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Router;
    use axum_test::TestServer;
    use tokio::time;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn metrics_handle_message_increments_counter_successfully() {
        let (router, process, client) = create_endpoint();
        _ = process.run(CancellationToken::new());

        let router = Router::new().route("/test", router);
        let server = TestServer::new(router).unwrap();

        let initial_metrics = server.get("/test").await;
        initial_metrics.assert_text_contains("blocks_received 0");
        initial_metrics.assert_status_ok();

        client.record_metric(Msg::IncBlockReceived).unwrap();
        client.record_metric(Msg::IncBlockReceived).unwrap();
        client.record_metric(Msg::IncBlockReceived).unwrap();

        // Wait for the metrics to be updated
        time::sleep(Duration::from_secs(1)).await;
        let final_metrics = server.get("/test").await;
        final_metrics.assert_text_contains("blocks_received 3");
        final_metrics.assert_status_ok();

        // Ensure the final metrics are in the expected format
        goldie::assert!(final_metrics.text())
    }
}

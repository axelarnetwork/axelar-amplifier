use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, MethodRouter};
use error_stack::{Result, ResultExt};
use futures::StreamExt;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::log::warn;

// safe upper bound for expected metric throughput;
// shouldn't exceed 1000 message
const CHANNEL_SIZE: usize = 1000;

/// content-Type for Prometheus/OpenMetrics text format responses.
const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Messages for metrics collection
///
/// These messages are sent to the metrics processor to update various counters
/// and gauges tracked by the monitoring system.
#[derive(Clone)]
pub enum Msg {
    /// Increment the count of blocks received
    BlockReceived,
    // Increment the count of succeeded votes casted by verifier
    VoteSucceeded {
        verifier_id: String,
        chain_name: String,
    },
    // Increment the count of failed votes (either broadcast or handler error) by verifier
    VoteFailed {
        verifier_id: String,
        chain_name: String,
    },
}

/// Errors that can occur in metrics processing
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    MetricsEncoding(#[from] std::fmt::Error),
    #[error(transparent)]
    HttpResponse(#[from] axum::http::Error),
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

    let mut registry = <Registry>::default();
    let metrics = Metrics::new(&mut registry);

    (
        get(serve_metrics).with_state(Arc::new(registry)),
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

async fn serve_metrics(
    State(registry): State<Arc<Registry>>,
) -> core::result::Result<Response<Body>, Error> {
    let mut buffer = String::new();
    encode(&mut buffer, &registry)?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, OPENMETRICS_CONTENT_TYPE)
        .body(Body::from(buffer))?;
    Ok(response)
}

struct Metrics {
    blocks_received: BlockReceivedMetrics,
    votes: VoteMetrics,
}

struct BlockReceivedMetrics {
    total: Counter,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct VoteLabel {
    verifier_id: String,
    chain_name: String,
}

struct VoteMetrics {
    succeeded: Family<VoteLabel, Counter>,
    failed: Family<VoteLabel, Counter>,
    success_rate: Family<VoteLabel, Gauge<f64, AtomicU64>>,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        // all created metrics are static, so errors during registration are bugs and should panic
        let blocks_received = BlockReceivedMetrics::new();
        let votes = VoteMetrics::new();

        blocks_received.register(registry);
        votes.register(registry);

        Self {
            blocks_received,
            votes,
        }
    }

    pub fn handle_message(&self, msg: Msg) {
        match msg {
            Msg::BlockReceived => {
                self.blocks_received.increment();
            }

            Msg::VoteSucceeded {
                verifier_id,
                chain_name,
            } => {
                self.votes.record_vote(verifier_id, chain_name, true);
            }
            Msg::VoteFailed {
                verifier_id,
                chain_name,
            } => {
                self.votes.record_vote(verifier_id, chain_name, false);
            }
        }
    }
}

impl BlockReceivedMetrics {
    fn new() -> Self {
        let total = Counter::default();
        Self { total }
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(
            "blocks_received",
            "number of blocks received",
            self.total.clone(),
        )
    }

    fn increment(&self) {
        self.total.inc();
    }
}

impl VoteMetrics {
    fn new() -> Self {
        let succeeded = Family::<VoteLabel, Counter>::default();
        let failed = Family::<VoteLabel, Counter>::default();
        let success_rate = Family::<VoteLabel, Gauge<f64, AtomicU64>>::default();

        Self {
            succeeded,
            failed,
            success_rate,
        }
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(
            "verifier_votes_successful",
            "number of successful votes casts by verifier",
            self.succeeded.clone(),
        );
        registry.register(
            "verifier_votes_failed",
            "number of failed votes by verifier (handler/broadcast errors)",
            self.failed.clone(),
        );
        registry.register(
            "verifier_votes_success_rate",
            "success rate of votes casts by verifier",
            self.success_rate.clone(),
        );
    }

    fn record_vote(&self, verifier_id: String, chain_name: String, success: bool) {
        let label = VoteLabel::new(verifier_id, chain_name);
        match success {
            true => {
                self.succeeded.get_or_create(&label).inc();
            }
            false => {
                self.failed.get_or_create(&label).inc();
            }
        }

        self.update_success_rate(&label);
    }

    fn update_success_rate(&self, label: &VoteLabel) {
        let succeeded_votes = self.succeeded.get_or_create(label).get();
        let failed_votes = self.failed.get_or_create(label).get();

        let total_votes = succeeded_votes.wrapping_add(failed_votes);

        let success_rate = match total_votes {
            0 => 0.0, // avoid division by zero, would only happen if overflow
            _ => succeeded_votes as f64 / total_votes as f64,
        };

        self.success_rate.get_or_create(label).set(success_rate);
    }
}

impl VoteLabel {
    fn new(verifier_id: String, chain_name: String) -> Self {
        Self {
            verifier_id,
            chain_name,
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
    async fn should_increment_blocks_received_counter_when_message_processed() {
        let (router, process, client) = create_endpoint();
        _ = process.run(CancellationToken::new());

        let router = Router::new().route("/test", router);
        let server = TestServer::new(router).unwrap();

        let initial_metrics = server.get("/test").await;

        initial_metrics.assert_text_contains("blocks_received_total 0");
        initial_metrics.assert_status_ok();

        client.record_metric(Msg::BlockReceived).unwrap();
        client.record_metric(Msg::BlockReceived).unwrap();
        client.record_metric(Msg::BlockReceived).unwrap();

        // Wait for the metrics to be updated
        time::sleep(Duration::from_secs(1)).await;
        let final_metrics = server.get("/test").await;
        final_metrics.assert_text_contains("blocks_received_total 3");
        final_metrics.assert_status_ok();

        // Ensure the final metrics are in the expected format
        goldie::assert!(final_metrics.text())
    }

    #[tokio::test(start_paused = true)]
    async fn should_update_vote_metrics_correctly_when_multiple_chains_cast_votes() {
        let (router, process, client) = create_endpoint();
        _ = process.run(CancellationToken::new());

        let router = Router::new().route("/test", router);
        let server = TestServer::new(router).unwrap();

        for _ in 0..2 {
            client
                .record_metric(Msg::VoteSucceeded {
                    chain_name: "ethereum".to_string(),
                    verifier_id: "axelar1abc".to_string(),
                })
                .unwrap();

            client
                .record_metric(Msg::VoteFailed {
                    chain_name: "ethereum".to_string(),
                    verifier_id: "axelar1abc".to_string(),
                })
                .unwrap();
        }

        client
            .record_metric(Msg::VoteSucceeded {
                chain_name: "sui".to_string(),
                verifier_id: "suiabc".to_string(),
            })
            .unwrap();

        time::sleep(Duration::from_secs(1)).await;
        let metrics = server.get("/test").await;

        let sorted_metrics = sort_metrics_text(metrics.text());
        goldie::assert!(sorted_metrics);

        metrics.assert_status_ok();
    }

    /// Sort metrics text alphabetically by line.
    ///
    /// The prometheus_client crate returns metrics in non-deterministic order
    /// when there are metrics with more than one label. We sort them before
    /// using golden file tests to ensure consistent output.
    fn sort_metrics_text(metrics_text: String) -> String {
        let mut lines: Vec<&str> = metrics_text.lines().collect();
        lines.sort();
        lines.join("\n")
    }
}

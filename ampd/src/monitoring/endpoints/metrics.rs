use std::sync::Arc;

use axelar_wasm_std::voting::Vote;
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
#[derive(Clone, PartialEq, Debug)]
pub enum Msg {
    /// Increment the count of blocks received
    BlockReceived,
    /// Record the vote verification results for cross-chain message
    VoteVerification {
        vote_status: Vote,
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
#[derive(Clone, Debug)]
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
    block_received: BlockReceivedMetrics,
    vote_verification: VoteVerificationMetrics,
}

struct BlockReceivedMetrics {
    total: Counter,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct VoteStatusLabel {
    /// source chain name of the handler
    chain_name: String,
    /// the vote verification outcome
    ///
    /// - succeeded_on_chain: the message was verified successfully on source chain
    /// - failed_on_chain: the message was found but verification failed on source chain
    /// - not_found: the message was not found on source chain
    status: String,
}

struct VoteVerificationMetrics {
    total: Family<VoteStatusLabel, Counter>,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let block_received = BlockReceivedMetrics::new();
        let vote_verification = VoteVerificationMetrics::new();

        block_received.register(registry);
        vote_verification.register(registry);

        Self {
            block_received,
            vote_verification,
        }
    }

    pub fn handle_message(&self, msg: Msg) {
        match msg {
            Msg::BlockReceived => {
                self.block_received.increment();
            }

            Msg::VoteVerification {
                vote_status,
                chain_name,
            } => {
                self.vote_verification
                    .record_vote_verification(vote_status, chain_name);
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
        );
    }

    fn increment(&self) {
        self.total.inc();
    }
}

impl VoteVerificationMetrics {
    fn new() -> Self {
        let total = Family::<VoteStatusLabel, Counter>::default();
        Self { total }
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(
            "vote_verification_total",
            "number of messages verification votes",
            self.total.clone(),
        );
    }

    fn record_vote_verification(&self, status: Vote, chain_name: String) {
        let status = match status {
            Vote::SucceededOnChain => "succeeded_on_chain".to_string(),
            Vote::FailedOnChain => "failed_on_chain".to_string(),
            Vote::NotFound => "not_found".to_string(),
        };

        let label = VoteStatusLabel { chain_name, status };
        self.total.get_or_create(&label).inc();
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
    async fn should_update_vote_verification_metrics_correctly_when_multiple_chains_cast_votes() {
        let (router, process, client) = create_endpoint();
        _ = process.run(CancellationToken::new());

        let router = Router::new().route("/test", router);
        let server = TestServer::new(router).unwrap();

        let initial_metrics = server.get("/test").await;
        initial_metrics.assert_status_ok();

        let chain_names = vec!["ethereum", "solana", "polygon", "avalanche", "stellar"];

        for chain_name in chain_names {
            client
                .record_metric(Msg::VoteVerification {
                    vote_status: Vote::SucceededOnChain,
                    chain_name: chain_name.to_string(),
                })
                .unwrap();
            client
                .record_metric(Msg::VoteVerification {
                    vote_status: Vote::FailedOnChain,
                    chain_name: chain_name.to_string(),
                })
                .unwrap();
            client
                .record_metric(Msg::VoteVerification {
                    vote_status: Vote::NotFound,
                    chain_name: chain_name.to_string(),
                })
                .unwrap();
        }

        time::sleep(Duration::from_secs(1)).await;
        let final_metrics = server.get("/test").await;
        final_metrics.assert_status_ok();

        goldie::assert!(sort_metrics_output(&final_metrics.text()))
    }

    #[test]
    fn should_provide_consistent_sorted_output() {
        let unsorted_output1 =
            include_str!("testdata/metrics_sorting/unsorted_metrics_version_1.txt");
        let unsorted_output2 =
            include_str!("testdata/metrics_sorting/unsorted_metrics_version_2.txt");

        let sorted_data1 = sort_metrics_output(unsorted_output1);
        let sorted_data2 = sort_metrics_output(unsorted_output2);

        assert_eq!(sorted_data1, sorted_data2);
        goldie::assert!(sorted_data1);
    }

    /// Sort metrics text alphabetically by line for consistent output
    ///
    /// The prometheus_client crate returns metrics in non-deterministic order
    /// when there are metrics with more than one label.  This function sorts
    /// the metrics output to ensure consistent output in golden file tests.
    pub fn sort_metrics_output(buffer: &str) -> String {
        let mut result = Vec::new();
        let mut current_headers = Vec::new();
        let mut current_metrics = Vec::new();

        for line in buffer.lines() {
            if line.starts_with("# TYPE") {
                current_headers.push(line.to_string());
            } else if line.starts_with("#") {
                if !current_headers.is_empty() {
                    result.append(&mut current_headers);

                    current_metrics.sort();
                    result.append(&mut current_metrics);
                }
                if line.starts_with("# HELP") {
                    current_headers.push(line.to_string());
                } else if line.starts_with("# EOF") {
                    result.push(line.to_string());
                }
            } else {
                current_metrics.push(line.to_string());
            }
        }

        result.join("\n") + "\n"
    }
}

use std::sync::Arc;

use axelar_wasm_std::voting;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, MethodRouter};
use futures::StreamExt;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use router_api::ChainName;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::warn;

// safe upper bound for expected metric throughput;
// shouldn't exceed 1000 message
const CHANNEL_SIZE: usize = 1000;

/// content-Type for Prometheus/OpenMetrics text format responses.
const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Messages for metrics collection
///
/// These messages are sent to the metrics processor to update various counters
/// and gauges tracked by the monitoring system.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Msg {
    /// Increment the count of blocks received
    BlockReceived,
    /// Record the verification vote results for cross-chain message
    VerificationVote {
        vote_decision: voting::Vote,
        chain_name: ChainName,
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
    ///    - If sending fails, a warning is logged
    ///    - [`record_metric`] should never disrupt the main flow of the application
    pub fn record_metric(&self, msg: Msg) {
        match self {
            Client::Disabled => (),
            Client::WithChannel { sender } => {
                if let Err(err) = sender.try_send(msg.clone()) {
                    warn!(error = %err, msg = ?msg, "failed to record metrics");
                }
            }
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
    verification_vote: VerificationVoteMetrics,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let block_received = BlockReceivedMetrics::new();
        let verification_vote = VerificationVoteMetrics::new();

        block_received.register(registry);
        verification_vote.register(registry);

        Self {
            block_received,
            verification_vote,
        }
    }

    pub fn handle_message(&self, msg: Msg) {
        match msg {
            Msg::BlockReceived => {
                self.block_received.increment();
            }

            Msg::VerificationVote {
                vote_decision,
                chain_name,
            } => {
                self.verification_vote
                    .record_verification_vote(vote_decision, chain_name);
            }
        }
    }
}

struct BlockReceivedMetrics {
    total: Counter,
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

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
enum Vote {
    SucceededOnChain,
    FailedOnChain,
    NotFound,
}

impl From<voting::Vote> for Vote {
    fn from(vote: voting::Vote) -> Self {
        match vote {
            voting::Vote::SucceededOnChain => Vote::SucceededOnChain,
            voting::Vote::FailedOnChain => Vote::FailedOnChain,
            voting::Vote::NotFound => Vote::NotFound,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct VerificationVoteLabel {
    /// Source chain name of the handler
    chain_name: String,
    /// The verification vote decision
    vote_decision: Vote,
}

struct VerificationVoteMetrics {
    total: Family<VerificationVoteLabel, Counter>,
}

impl VerificationVoteMetrics {
    fn new() -> Self {
        let total = Family::<VerificationVoteLabel, Counter>::default();
        Self { total }
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(
            "verification_votes",
            "number of verification votes on cross-chain messages",
            self.total.clone(),
        );
    }

    fn record_verification_vote(&self, vote_decision: voting::Vote, chain_name: ChainName) {
        let chain_name = chain_name.to_string();
        let vote_decision: Vote = vote_decision.into();

        let label = VerificationVoteLabel {
            chain_name,
            vote_decision,
        };
        self.total.get_or_create(&label).inc();
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use axum::Router;
    use axum_test::TestServer;
    use itertools::Itertools;
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

        client.record_metric(Msg::BlockReceived);
        client.record_metric(Msg::BlockReceived);
        client.record_metric(Msg::BlockReceived);

        // Wait for the metrics to be updated
        time::sleep(Duration::from_secs(1)).await;
        let final_metrics = server.get("/test").await;
        final_metrics.assert_text_contains("blocks_received_total 3");
        final_metrics.assert_status_ok();

        // Ensure the final metrics are in the expected format
        goldie::assert!(final_metrics.text())
    }

    #[tokio::test(start_paused = true)]
    async fn should_update_verification_votes_metrics_correctly_when_multiple_chains_cast_votes() {
        let (router, process, client) = create_endpoint();
        _ = process.run(CancellationToken::new());

        let router = Router::new().route("/test", router);
        let server = TestServer::new(router).unwrap();

        let initial_metrics = server.get("/test").await;
        initial_metrics.assert_status_ok();

        let chain_names = vec![
            ChainName::from_str("ethereum").unwrap(),
            ChainName::from_str("solana").unwrap(),
            ChainName::from_str("polygon").unwrap(),
            ChainName::from_str("avalanche").unwrap(),
            ChainName::from_str("stellar").unwrap(),
        ];

        for chain_name in chain_names {
            client.record_metric(Msg::VerificationVote {
                vote_decision: voting::Vote::SucceededOnChain,
                chain_name: chain_name.clone(),
            });
            client.record_metric(Msg::VerificationVote {
                vote_decision: voting::Vote::FailedOnChain,
                chain_name: chain_name.clone(),
            });
            client.record_metric(Msg::VerificationVote {
                vote_decision: voting::Vote::NotFound,
                chain_name: chain_name.clone(),
            });
        }

        time::sleep(Duration::from_secs(1)).await;
        let final_metrics = server.get("/test").await;
        final_metrics.assert_status_ok();

        goldie::assert!(sort_metrics_output(&final_metrics.text()))
    }

    /// Test if the sort_metrics_output function produces consistent output.
    /// This validates the test infrastructure itself, not the metrics implementation.
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
    /// when there are metrics with more than one label. This function sorts
    /// the metrics output to ensure consistent output in golden file tests.
    fn sort_metrics_output(buffer: &str) -> String {
        let mut lines = buffer.lines().peekable();
        let mut result = Vec::new();

        while lines.peek().is_some() {
            let header_lines: Vec<String> = lines
                .take_while_ref(|l| l.starts_with("#"))
                .map(|line| line.to_string())
                .collect();

            result.extend(header_lines);

            let mut metric_lines: Vec<String> = lines
                .take_while_ref(|l| !l.starts_with("#"))
                .map(|line| line.to_string())
                .collect();

            metric_lines.sort();
            result.extend(metric_lines);
        }

        result.join("\n") + "\n"
    }
}

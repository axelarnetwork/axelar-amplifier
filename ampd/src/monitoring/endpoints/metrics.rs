use std::sync::Arc;
use std::time::Duration;

use axelar_wasm_std::voting::Vote;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, MethodRouter};
use futures::StreamExt;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
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

#[derive(Clone, PartialEq, Debug)]
pub enum TransactionExecutionStatus {
    SucceededOnChain,
    FailedOnChain,
    NotFound,
    QueryError,
}

/// Messages for metrics collection
///
/// These messages are sent to the metrics processor to update various counters
/// and gauges tracked by the monitoring system.
#[derive(Clone, PartialEq, Debug)]
pub enum Msg {
    /// Increment the count of blocks received
    BlockReceived,
    /// Record the verification vote results for cross-chain message
    VerificationVote {
        vote_status: Vote,
        chain_name: String,
    },
    /// Record the transaction broadcast results and duration
    TransactionBroadcast { success: bool, duration: Duration },
    /// Record the transaction confirmation duration
    /// Duration is only recorded for transactions that were successfully
    /// queried from the blockchain: SucceededOnChain or FailedOnChain
    /// NotFound or QueryError are not recorded because they always reaches the timeout limit
    TransactionConfirmed {
        status: TransactionExecutionStatus,
        duration: Duration,
    },
    /// Record the transaction execution status
    TransactionExecutionStatus { status: TransactionExecutionStatus },
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
    /// - If sending fails, a warning is logged
    /// - record_metrics should never disrupt the main flow of the application
    pub fn record_metric(&self, msg: Msg) {
        match self {
            Client::Disabled => (),
            Client::WithChannel { sender } => {
                if let Err(err) = sender.try_send(msg.clone()) {
                    warn!(
                        "failed to record metrics message: {:?}, with error: {:?}",
                        msg, err
                    );
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
    transaction_processed: TransactionMetrics,
}

struct BlockReceivedMetrics {
    total: Counter,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]

struct TransactionLabel {
    status: String,
}

struct TransactionMetrics {
    broadcast: TransactionBroadcastMetrics,
    confirmation_duration: TransactionConfirmationMetrics,
    execution_status: TransactionExecutionStatusMetrics,
}

struct TransactionBroadcastMetrics {
    total: Family<TransactionLabel, Counter>,
    duration: Family<TransactionLabel, Histogram>,
}

struct TransactionConfirmationMetrics {
    duration: Family<TransactionLabel, Histogram>,
}

struct TransactionExecutionStatusMetrics {
    total: Family<TransactionLabel, Counter>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct VerificationVoteLabel {
    /// source chain name of the handler
    chain_name: String,
    /// the verification vote outcome
    ///
    /// - succeeded_on_chain: the message was verified successfully on source chain
    /// - failed_on_chain: the message was found but verification failed on source chain
    /// - not_found: the message was not found on source chain
    status: String,
}

struct VerificationVoteMetrics {
    total: Family<VerificationVoteLabel, Counter>,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let block_received = BlockReceivedMetrics::new();
        let verification_vote = VerificationVoteMetrics::new();
        let transaction_processed = TransactionMetrics::new();

        block_received.register(registry);
        verification_vote.register(registry);
        transaction_processed.register(registry);

        Self {
            block_received,
            verification_vote,
            transaction_processed,
        }
    }

    pub fn handle_message(&self, msg: Msg) {
        match msg {
            Msg::BlockReceived => {
                self.block_received.increment();
            }

            Msg::VerificationVote {
                vote_status,
                chain_name,
            } => {
                self.verification_vote
                    .record_verification_vote(vote_status, chain_name);
            }
            Msg::TransactionBroadcast { success, duration } => {
                self.transaction_processed
                    .broadcast
                    .record_transaction_broadcast(success, duration);
            }

            Msg::TransactionConfirmed { status, duration } => {
                self.transaction_processed
                    .confirmation_duration
                    .record_transaction_confirmation(status, duration);
            }

            Msg::TransactionExecutionStatus { status } => {
                self.transaction_processed
                    .execution_status
                    .record_status(status);
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

    fn record_verification_vote(&self, status: Vote, chain_name: String) {
        let status = match status {
            Vote::SucceededOnChain => "succeeded_on_chain".to_string(),
            Vote::FailedOnChain => "failed_on_chain".to_string(),
            Vote::NotFound => "not_found".to_string(),
        };

        let label = VerificationVoteLabel { chain_name, status };
        self.total.get_or_create(&label).inc();
    }
}

impl TransactionMetrics {
    fn new() -> Self {
        let broadcast = TransactionBroadcastMetrics::new();
        let confirmation_duration = TransactionConfirmationMetrics::new();
        let execution_status = TransactionExecutionStatusMetrics::new();
        Self {
            broadcast,
            confirmation_duration,
            execution_status,
        }
    }

    fn register(&self, registry: &mut Registry) {
        self.broadcast.register(registry);
        self.confirmation_duration.register(registry);
        self.execution_status.register(registry);
    }
}
impl TransactionConfirmationMetrics {
    fn new() -> Self {
        let duration = Family::<TransactionLabel, Histogram>::new_with_constructor(|| {
            Histogram::new(vec![0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 5.5, 6.0, 10.0])
        });
        Self { duration }
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(
            "ampd_transaction_confirmation_duration_seconds",
            "Duration of successful blockchain queries for transaction confirmation in seconds",
            self.duration.clone(),
        );
    }

    fn record_transaction_confirmation(
        &self,
        status: TransactionExecutionStatus,
        duration: Duration,
    ) {
        let status = match status {
            TransactionExecutionStatus::SucceededOnChain => "succeeded_on_chain".to_string(),
            TransactionExecutionStatus::FailedOnChain => "failed_on_chain".to_string(),
            _ => "".to_string(), // only succeeded_on_chain and failed_on_chain are recorded, this should never happen
        };

        let label = TransactionLabel { status };

        self.duration
            .get_or_create(&label)
            .observe(duration.as_secs_f64());
    }
}

impl TransactionBroadcastMetrics {
    fn new() -> Self {
        let total = Family::<TransactionLabel, Counter>::default();
        let duration = Family::<TransactionLabel, Histogram>::new_with_constructor(|| {
            Histogram::new(vec![0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0])
        });

        Self { total, duration }
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(
            "ampd_transaction_broadcast",
            "number of transactions broadcast by the ampd",
            self.total.clone(),
        );
        registry.register(
            "ampd_transaction_broadcast_duration_seconds",
            "Duration of transaction broadcast in seconds",
            self.duration.clone(),
        );
    }

    fn record_transaction_broadcast(&self, success: bool, duration: Duration) {
        let status = match success {
            true => "success".to_string(),
            false => "failure".to_string(),
        };
        let label = TransactionLabel { status };

        self.total.get_or_create(&label).inc();

        self.duration
            .get_or_create(&label)
            .observe(duration.as_secs_f64());
    }
}

impl TransactionExecutionStatusMetrics {
    fn new() -> Self {
        let total = Family::<TransactionLabel, Counter>::default();
        Self { total }
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(
            "ampd_transaction_execution_results",
            "number of transaction execution results by status",
            self.total.clone(),
        );
    }

    fn record_status(&self, status: TransactionExecutionStatus) {
        let status = match status {
            TransactionExecutionStatus::SucceededOnChain => "succeeded_on_chain".to_string(),
            TransactionExecutionStatus::FailedOnChain => "failed_on_chain".to_string(),
            TransactionExecutionStatus::NotFound => "not_found".to_string(),
            TransactionExecutionStatus::QueryError => "query_error".to_string(),
        };

        let label = TransactionLabel { status };
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

        let chain_names = vec!["ethereum", "solana", "polygon", "avalanche", "stellar"];

        for chain_name in chain_names {
            client.record_metric(Msg::VerificationVote {
                vote_status: Vote::SucceededOnChain,
                chain_name: chain_name.to_string(),
            });
            client.record_metric(Msg::VerificationVote {
                vote_status: Vote::FailedOnChain,
                chain_name: chain_name.to_string(),
            });
            client.record_metric(Msg::VerificationVote {
                vote_status: Vote::NotFound,
                chain_name: chain_name.to_string(),
            });
        }

        time::sleep(Duration::from_secs(1)).await;
        let final_metrics = server.get("/test").await;
        final_metrics.assert_status_ok();

        println!("{}", final_metrics.text());

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

    #[tokio::test(start_paused = true)]
    async fn should_record_transaction_broadcast_result_successfully() {
        let (router, process, client) = create_endpoint();
        _ = process.run(CancellationToken::new());

        let router = Router::new().route("/test", router);
        let server = TestServer::new(router).unwrap();

        let initial_metrics = server.get("/test").await;
        initial_metrics.assert_status_ok();

        client.record_metric(Msg::TransactionBroadcast {
            success: true,
            duration: Duration::from_secs(1),
        });
        client.record_metric(Msg::TransactionBroadcast {
            success: true,
            duration: Duration::from_secs(2),
        });
        client.record_metric(Msg::TransactionBroadcast {
            success: true,
            duration: Duration::from_secs(2),
        });
        client.record_metric(Msg::TransactionBroadcast {
            success: false,
            duration: Duration::from_secs(3),
        });

        time::sleep(Duration::from_secs(1)).await;
        let final_metrics = server.get("/test").await;
        goldie::assert!(sort_metrics_output(&final_metrics.text()))
    }

    #[tokio::test(start_paused = true)]
    async fn should_record_transaction_confirmation_result_successfully() {
        let (router, process, client) = create_endpoint();
        _ = process.run(CancellationToken::new());

        let router = Router::new().route("/test", router);
        let server = TestServer::new(router).unwrap();

        let initial_metrics = server.get("/test").await;
        initial_metrics.assert_status_ok();

        client.record_metric(Msg::TransactionConfirmed {
            status: TransactionExecutionStatus::SucceededOnChain,
            duration: Duration::from_secs(1),
        });
        client.record_metric(Msg::TransactionConfirmed {
            status: TransactionExecutionStatus::SucceededOnChain,
            duration: Duration::from_secs(2),
        });
        client.record_metric(Msg::TransactionConfirmed {
            status: TransactionExecutionStatus::SucceededOnChain,
            duration: Duration::from_secs(2),
        });
        client.record_metric(Msg::TransactionConfirmed {
            status: TransactionExecutionStatus::FailedOnChain,
            duration: Duration::from_secs(3),
        });

        time::sleep(Duration::from_secs(1)).await;
        let final_metrics = server.get("/test").await;
        goldie::assert!(sort_metrics_output(&final_metrics.text()))
    }

    #[tokio::test(start_paused = true)]
    async fn should_record_transaction_execution_status_successfully() {
        let (router, process, client) = create_endpoint();
        _ = process.run(CancellationToken::new());

        let router = Router::new().route("/test", router);
        let server = TestServer::new(router).unwrap();

        let initial_metrics = server.get("/test").await;
        initial_metrics.assert_status_ok();

        client.record_metric(Msg::TransactionExecutionStatus {
            status: TransactionExecutionStatus::SucceededOnChain,
        });
        client.record_metric(Msg::TransactionExecutionStatus {
            status: TransactionExecutionStatus::FailedOnChain,
        });
        client.record_metric(Msg::TransactionExecutionStatus {
            status: TransactionExecutionStatus::NotFound,
        });
        client.record_metric(Msg::TransactionExecutionStatus {
            status: TransactionExecutionStatus::QueryError,
        });

        time::sleep(Duration::from_secs(1)).await;
        let final_metrics = server.get("/test").await;
        goldie::assert!(sort_metrics_output(&final_metrics.text()))
    }
}

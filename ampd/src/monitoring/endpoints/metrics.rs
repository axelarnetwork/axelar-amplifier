use std::sync::{Arc, Mutex};

use axelar_wasm_std::voting;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, MethodRouter};
use futures::StreamExt;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::{
    DescriptorEncoder, EncodeLabelSet, EncodeLabelValue, EncodeMetric,
};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::ConstGauge;
use prometheus_client::registry::{Registry, Unit};
use router_api::ChainName;
use sysinfo::{get_current_pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::warn;

// safe upper bound for expected metric throughput;
// shouldn't exceed 1000 message
const CHANNEL_SIZE: usize = 1000;

/// content-Type for Prometheus/OpenMetrics text format responses.
const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Stage {
    EventHandling,
    TransactionBroadcast,
    TransactionConfirmation,
}
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
    /// Record the result of RPC calls
    RpcCall {
        chain_name: ChainName,
        success: bool,
    },
    /// Record result and duration of a processing stage operation
    StageResult {
        stage: Stage,
        success: bool,
        duration: Duration,
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
    registry.register_collector(Box::new(SystemMetricsCollector::new()));

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
    rpc_call: RpcCallMetrics,
    stage_result: EventStageMetrics,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let block_received = BlockReceivedMetrics::new();
        let verification_vote = VerificationVoteMetrics::new();
        let rpc_call = RpcCallMetrics::new();
        let stage_result = EventStageMetrics::new();

        block_received.register(registry);
        verification_vote.register(registry);
        rpc_call.register(registry);
        stage_result.register(registry);

        Self {
            block_received,
            verification_vote,
            rpc_call,
            stage_result,
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

            Msg::RpcCall {
                chain_name,
                success,
            } => {
                self.rpc_call.record_rpc_call(chain_name, success);
            }
            Msg::StageResult {
                stage,
                success,
                duration,
            } => {
                self.stage_result.record(success, duration, stage);
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

struct RpcCallMetrics {
    total: Family<Vec<(String, String)>, Counter>,
    failed: Family<Vec<(String, String)>, Counter>,
}

impl RpcCallMetrics {
    fn new() -> Self {
        let total = Family::<Vec<(String, String)>, Counter>::default();
        let failed = Family::<Vec<(String, String)>, Counter>::default();
        Self { total, failed }
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(
            "rpc_calls",
            "number of RPC calls per chain",
            self.total.clone(),
        );

        registry.register(
            "rpc_calls_failed",
            "number of failed RPC calls per chain",
            self.failed.clone(),
        );
    }

    fn record_rpc_call(&self, chain_name: ChainName, success: bool) {
        let label = vec![("chain_name".to_string(), chain_name.to_string())];
        self.total.get_or_create(&label).inc();

        if !success {
            self.failed.get_or_create(&label).inc();
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct StageLabel {
    stage: Stage,
}

struct EventStageMetrics {
    total: Family<StageLabel, Counter>,
    failed: Family<StageLabel, Counter>,
    duration: Family<StageLabel, Counter>,
}

impl EventStageMetrics {
    fn new() -> Self {
        let total = Family::<StageLabel, Counter>::default();
        let failed = Family::<StageLabel, Counter>::default();
        let duration = Family::<StageLabel, Counter>::default();
        Self {
            total,
            failed,
            duration,
        }
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(
            "stage_processed",
            "total number of processed items per stage",
            self.total.clone(),
        );
        registry.register(
            "stage_failed",
            "number of failed items per stage",
            self.failed.clone(),
        );
        registry.register(
            "stage_duration",
            "duration of processing items per stage in milliseconds",
            self.duration.clone(),
        );
    }

    fn record(&self, success: bool, duration: Duration, stage: Stage) {
        let label = StageLabel { stage };
        self.total.get_or_create(&label).inc();
        if !success {
            self.failed.get_or_create(&label).inc();
        }
        self.duration
            .get_or_create(&label)
            .inc_by(duration.as_millis() as u64);
    }
}

/// Generic function to time an async operation and return both result and duration.
/// Used when recording EventFlow metrics.
pub async fn timed<F, Fut, T>(f: F) -> (T, Duration)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let start = Instant::now();
    let result = f().await;
    let elapsed = start.elapsed();
    (result, elapsed)
}

/// System metrics collector that provides real-time CPU and memory usage for the AMPD process.
/// Metrics are collected fresh on each scrape request using the sysinfo crate.
/// when metrics is not available, no system metrics will be returned.
/// this may happen because of permission issues, process termination, or platform limitations
#[derive(Debug)]
struct SystemMetricsCollector {
    system: Mutex<System>, // Mutex is required for thread-safe access since the registry may call this collector from multiple threads
}

#[derive(Debug, Clone)]
struct ProcessMetrics {
    cpu_usage: f32,
    memory_usage: u64,
}

impl SystemMetricsCollector {
    fn new() -> Self {
        let system = System::new_with_specifics(
            RefreshKind::nothing()
                .with_processes(ProcessRefreshKind::nothing().with_cpu().with_memory()),
        );
        Self {
            system: Mutex::new(system),
        }
    }

    fn collect_process_metrics(&self) -> Option<ProcessMetrics> {
        let pid = get_current_pid().ok()?;

        let mut system = self
            .system
            .lock()
            .inspect_err(|_| warn!("failed to acquire system metrics lock"))
            .ok()?;

        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );

        system.process(pid).map(|process| ProcessMetrics {
            cpu_usage: process.cpu_usage(),
            memory_usage: process.memory(),
        })
    }
}

impl Collector for SystemMetricsCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let process_metrics = match self.collect_process_metrics() {
            Some(metrics) => metrics,
            None => return Ok(()),
        };

        // Encode CPU Usage
        let cpu_gauge = ConstGauge::<f32>::new(process_metrics.cpu_usage);
        let unit = Unit::Other("percent".to_string());
        let cpu_encoder = encoder.encode_descriptor(
            "ampd_cpu_usage",
            "CPU usage of the ampd process in percentage",
            Some(&unit),
            cpu_gauge.metric_type(),
        )?;
        cpu_gauge.encode(cpu_encoder)?;

        // Encode Memory Usage
        let memory_gauge = ConstGauge::new(process_metrics.memory_usage);
        let memory_encoder = encoder.encode_descriptor(
            "ampd_memory_usage",
            "Memory usage of the ampd process in bytes",
            Some(&Unit::Bytes),
            memory_gauge.metric_type(),
        )?;
        memory_gauge.encode(memory_encoder)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use axum::Router;
    use axum_test::TestServer;
    use itertools::Itertools;
    use router_api::chain_name;
    use tokio::time;

    use super::test_utils::zeroize_system_metrics;
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn should_update_all_metrics_successfully() {
        let (router, process, client) = create_endpoint();
        _ = process.run(CancellationToken::new());

        let router = Router::new().route("/test", router);
        let server = TestServer::new(router).unwrap();

        let initial_metrics = server.get("/test").await;

        initial_metrics.assert_status_ok();

        // blocks received
        client.record_metric(Msg::BlockReceived);
        client.record_metric(Msg::BlockReceived);
        client.record_metric(Msg::BlockReceived);

        // verification votes
        let chain_names = vec![
            chain_name!("ethereum"),
            chain_name!("solana"),
            chain_name!("polygon"),
            chain_name!("avalanche"),
            chain_name!("stellar"),
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

        // EventFlow Metrics
        client.record_metric(Msg::StageResult {
            stage: Stage::EventHandling,
            success: true,
            duration: Duration::from_millis(100),
        });
        client.record_metric(Msg::StageResult {
            stage: Stage::EventHandling,
            success: false,
            duration: Duration::from_millis(200),
        });
        client.record_metric(Msg::StageResult {
            stage: Stage::TransactionBroadcast,
            success: true,
            duration: Duration::from_millis(300),
        });
        client.record_metric(Msg::StageResult {
            stage: Stage::TransactionBroadcast,
            success: false,
            duration: Duration::from_millis(400),
        });
        client.record_metric(Msg::StageResult {
            stage: Stage::TransactionConfirmation,
            success: true,
            duration: Duration::from_millis(500),
        });
        client.record_metric(Msg::StageResult {
            stage: Stage::TransactionConfirmation,
            success: false,
            duration: Duration::from_millis(600),
        });

        // Wait for the metrics to be updated
        // rpc calls
        client.record_metric(Msg::RpcCall {
            chain_name: ChainName::from_str("ethereum").unwrap(),
            success: true,
        });

        client.record_metric(Msg::RpcCall {
            chain_name: ChainName::from_str("polygon").unwrap(),
            success: false,
        });

        // Wait for the metrics to be updated
        time::sleep(Duration::from_secs(1)).await;
        let final_metrics = server.get("/test").await;

        final_metrics.assert_status_ok();

        // system metrics
        if final_metrics.text().contains("ampd_cpu_usage_percent") {
            let cpu_usage = extract_metric_value(&final_metrics.text(), "ampd_cpu_usage_percent");
            assert!(
                cpu_usage >= 0.0,
                "CPU usage should be non-negative when metric is present"
            );
        }

        if final_metrics.text().contains("ampd_memory_usage_bytes") {
            let memory_usage =
                extract_metric_value(&final_metrics.text(), "ampd_memory_usage_bytes");
            assert!(
                memory_usage >= 0.0,
                "Memory usage should be non-negative when metric is present"
            );
        }

        // Ensure the final metrics are in the expected format
        goldie::assert!(sort_metrics_output(&zeroize_system_metrics(
            &final_metrics.text()
        )))
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

    /// Extracts the numeric value of a Prometheus metric from text output
    fn extract_metric_value(text: &str, name: &str) -> f64 {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|num| num.parse::<f64>().ok())
            .unwrap_or_else(|| panic!("metric `{}` not found or not a number", name))
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

#[cfg(test)]
pub mod test_utils {
    use regex::Regex;

    /// System metrics like CPU and memory usage are inherently dynamic and change between test runs
    /// This function zeroizes the system metrics for consistent output in golden file tests.
    pub fn zeroize_system_metrics(text: &str) -> String {
        let mut result = Vec::new();
        let trailing_number = Regex::new(r"\d+(\.\d+)?$").unwrap();

        for line in text.lines() {
            if line.starts_with("ampd_cpu_usage_percent")
                || line.starts_with("ampd_memory_usage_bytes")
            {
                result.push(trailing_number.replace(line, "0").to_string());
            } else {
                result.push(line.to_string());
            }
        }
        result.join("\n") + "\n"
    }
}

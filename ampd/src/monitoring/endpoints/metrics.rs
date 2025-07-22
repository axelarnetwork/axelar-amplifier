use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

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
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use sysinfo::{get_current_pid, Pid, ProcessRefreshKind, ProcessesToUpdate, System};
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
#[derive(Clone, PartialEq, Debug)]
pub enum Msg {
    /// Increment the count of blocks received
    BlockReceived,
    /// Record the verification vote results for cross-chain message
    VerificationVote {
        vote_status: Vote,
        chain_name: String,
    },
    /// Update the system metrics for ampd process
    UpdateSystemMetrics { cpu_usage: f64, memory_usage: f64 },
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

#[derive(Clone)]
struct MetricsState {
    registry: Arc<Registry>,
    client: Client,
    system_metrics_collector: SystemMetricsCollector,
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
    let system_metrics_collector = SystemMetricsCollector::new();

    let client = Client::WithChannel { sender: tx };

    let state = MetricsState {
        registry: Arc::new(registry),
        client: client.clone(),
        system_metrics_collector,
    };

    (
        get(handle_metrics_request).with_state(state),
        Process::new(rx, metrics),
        client,
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

async fn handle_metrics_request(
    State(state): State<MetricsState>,
) -> core::result::Result<Response<Body>, Error> {
    update_system_metrics(&state);

    let mut buffer = String::new();
    encode(&mut buffer, &state.registry)?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, OPENMETRICS_CONTENT_TYPE)
        .body(Body::from(buffer))?;
    Ok(response)
}

fn update_system_metrics(state: &MetricsState) {
    let ProcessMetrics {
        cpu_usage,
        memory_usage,
    } = state.system_metrics_collector.collect_metrics();
    state.client.record_metric(Msg::UpdateSystemMetrics {
        cpu_usage,
        memory_usage,
    });
}

struct Metrics {
    block_received: BlockReceivedMetrics,
    verification_vote: VerificationVoteMetrics,
    system_info: SystemInfoMetrics,
}

struct SystemInfoMetrics {
    cpu_usage: Gauge<f64, AtomicU64>,
    memory_usage: Gauge<f64, AtomicU64>,
}

struct BlockReceivedMetrics {
    total: Counter,
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
        let system_info = SystemInfoMetrics::new();

        block_received.register(registry);
        verification_vote.register(registry);
        system_info.register(registry);

        Self {
            block_received,
            verification_vote,
            system_info,
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
            Msg::UpdateSystemMetrics {
                cpu_usage,
                memory_usage,
            } => {
                self.system_info.update_metrics(cpu_usage, memory_usage);
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

impl SystemInfoMetrics {
    fn new() -> Self {
        let cpu_usage = Gauge::<f64, AtomicU64>::default();
        let memory_usage = Gauge::<f64, AtomicU64>::default();
        Self {
            cpu_usage,
            memory_usage,
        }
    }

    fn register(&self, registry: &mut Registry) {
        registry.register(
            "cpu_usage",
            "ampd cpu usage in percentage",
            self.cpu_usage.clone(),
        );
        registry.register(
            "memory_usage",
            "ampd memory usage in bytes",
            self.memory_usage.clone(),
        );
    }

    fn update_metrics(&self, cpu_usage: f64, memory_usage: f64) {
        self.cpu_usage.set(cpu_usage);
        self.memory_usage.set(memory_usage);
    }
}

/// System metrics collector
///
/// This collector provides on-demand collection of CPU and memory metrics
/// for the current AMPD process. It gracefully handles platform limitations
/// and permission issues by falling back to dummy metrics when necessary.
///
/// `Available` - collect real system metrics from the OS
/// `Unavailable` - Returns zero metrics when system access is unavailable
#[derive(Debug, Clone)]
pub enum SystemMetricsCollector {
    Available(SysInfoCollector),
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct SysInfoCollector {
    system: Arc<Mutex<System>>,
    process_id: Pid,
}

#[derive(Debug, Clone)]
pub struct ProcessMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
}

impl SystemMetricsCollector {
    pub fn new() -> Self {
        match get_current_pid() {
            Ok(pid) => {
                let mut system = System::new();
                refresh_process_metrics(&mut system, pid);

                Self::Available(SysInfoCollector {
                    system: Arc::new(Mutex::new(system)),
                    process_id: pid,
                })
            }
            Err(e) => {
                warn!("system metrics is not available: {}", e);
                Self::Unavailable
            }
        }
    }

    pub fn collect_metrics(&self) -> ProcessMetrics {
        match self {
            Self::Available(collector) => collector.collect_metrics(),
            Self::Unavailable => ProcessMetrics {
                cpu_usage: 0.0,
                memory_usage: 0.0,
            },
        }
    }
}

/// Collects system metrics by querying the OS for process information.
/// CPU usage calculation requires two measurements over time. Since this is called
/// on-demand during Prometheus scraping, the measurement interval matches the scrape period.
/// This will calculate the average CPU usage between the scraping period.

impl SysInfoCollector {
    pub fn collect_metrics(&self) -> ProcessMetrics {
        let mut system = self.system.lock().unwrap();
        refresh_process_metrics(&mut system, self.process_id);

        match system.process(self.process_id) {
            Some(process) => ProcessMetrics {
                cpu_usage: process.cpu_usage() as f64,
                memory_usage: process.memory() as f64,
            },
            // if the process info is not found, return zero metrics and log a warning
            // this may happens because of permission issues, process termination, or platform limitations
            None => {
                warn!("system metrics is not available");
                ProcessMetrics {
                    cpu_usage: 0.0,
                    memory_usage: 0.0,
                }
            }
        }
    }
}

fn refresh_process_metrics(system: &mut System, process_id: Pid) {
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[process_id]),
        true,
        ProcessRefreshKind::nothing().with_cpu().with_memory(),
    );
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Router;
    use axum_test::TestServer;
    use tokio::time;
    use tracing_test::traced_test;

    use super::test_utils::filter_system_metrics_output;
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
        goldie::assert!(filter_system_metrics_output(&final_metrics.text()))
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

        goldie::assert!(sort_metrics_output(&filter_system_metrics_output(
            &final_metrics.text()
        )))
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

    #[tokio::test(start_paused = true)]
    #[traced_test]
    async fn should_show_valid_system_metrics_in_prometheus_output() {
        let (router, process, _client) = create_endpoint();
        _ = process.run(CancellationToken::new());

        let router = Router::new().route("/test", router);
        let server = TestServer::new(router).unwrap();

        let initial_metrics = server.get("/test").await;
        initial_metrics.assert_status_ok();
        time::sleep(Duration::from_secs(1)).await;

        let final_metrics = server.get("/test").await;
        final_metrics.assert_status_ok();

        let cpu_usage = metric_value(&final_metrics.text(), "cpu_usage");
        let memory_usage = metric_value(&final_metrics.text(), "memory_usage");

        assert!(
            cpu_usage >= 0.0,
            "CPU usage should be non-negative, got {}",
            cpu_usage
        );
        assert!(
            memory_usage >= 0.0,
            "Memory usage should be non-negative, got {}",
            memory_usage
        );

        // if the system metrics are not available, there should be a log message
        if cpu_usage == 0.0 || memory_usage == 0.0 {
            assert!(logs_contain("system metrics is not available"));
        }
    }

    /// Extracts the numeric value of a Prometheus metric from text output
    ///
    /// panic if the metric is not found or not a number
    /// used when asserting system metrics
    fn metric_value(text: &str, name: &str) -> f64 {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|num| num.parse::<f64>().ok())
            .unwrap_or_else(|| panic!("metric `{}` not found or not a number", name))
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

/// Filters out dynamic system metrics from Prometheus output for stable golden file tests
/// System metrics like CPU and memory usage are inherently dynamic and change between test runs
/// This function removes these metrics to create stable, predictable output for testing.
#[cfg(test)]
pub mod test_utils {
    pub fn filter_system_metrics_output(text: &str) -> String {
        let mut result = Vec::new();
        for line in text.lines() {
            if line.contains("cpu_usage") || line.contains("memory_usage") {
                continue;
            }
            result.push(line.to_string());
        }

        result.join("\n") + "\n"
    }
}

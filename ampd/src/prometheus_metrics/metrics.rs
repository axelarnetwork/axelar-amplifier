use error_stack::{Result, ResultExt};
use prometheus::{Encoder, IntCounter, Registry, TextEncoder};
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum MetricsMsg {
    IncBlockReceived,
}

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("failed to start metrics server")]
    Start,
    #[error("metrics server failed while running")]
    WhileRunning,
    #[error("failed to encode metrics")]
    EncodeError,
    #[error("failed to convert metrics to UTF-8")]
    Utf8Error,
    #[error("failed to update metric")]
    MetricUpdateFailed,
    #[error("failed to register metric")]
    MetricRegisterFailed,
    #[error("failed to spawn metric")]
    MetricSpawnFailed,
    #[error("counter not found: {0}")]
    CounterNotFound(String),
}

pub struct Metrics {
    block_received: IntCounter,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Result<Self, MetricsError> {
        let block_received = IntCounter::new("blocks_received", "number of blocks received")
            .change_context(MetricsError::MetricSpawnFailed)?;

        registry
            .register(Box::new(block_received.clone()))
            .change_context(MetricsError::MetricRegisterFailed)?;

        Ok(Self { block_received })
    }

    pub fn handle_message(&self, msg: MetricsMsg) {
        match msg {
            MetricsMsg::IncBlockReceived => {
                self.block_received.inc();
            }
        }
    }
}

pub fn gather(registry: &Registry) -> Result<String, MetricsError> {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();

    encoder
        .encode(&metric_families, &mut buffer)
        .change_context(MetricsError::EncodeError)?;

    String::from_utf8(buffer).change_context(MetricsError::Utf8Error)
}

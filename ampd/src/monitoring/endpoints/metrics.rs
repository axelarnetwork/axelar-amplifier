use axum::http::StatusCode;
use error_stack::{Result, ResultExt};
use prometheus::{Encoder, IntCounter, Registry, TextEncoder};
use thiserror::Error;

use crate::monitoring::MetricsMsg;

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("failed to start monitoring server")]
    Start,
    #[error("monitoring server failed while running")]
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

fn gather(registry: &Registry) -> Result<String, MetricsError> {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();

    encoder
        .encode(&metric_families, &mut buffer)
        .change_context(MetricsError::EncodeError)?;

    String::from_utf8(buffer).change_context(MetricsError::Utf8Error)
}

pub async fn gather_metrics(registry: &Registry) -> (StatusCode, String) {
    match gather(registry) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use prometheus::Registry;

    use super::*;

    #[test]
    fn metrics_handle_message_increments_counter_successfully() {
        let registry = Registry::new();
        let metrics = Metrics::new(&registry).unwrap();

        let initial_metrics = gather(&registry).unwrap();
        assert!(initial_metrics.contains("blocks_received 0"));

        metrics.handle_message(MetricsMsg::IncBlockReceived);
        metrics.handle_message(MetricsMsg::IncBlockReceived);
        metrics.handle_message(MetricsMsg::IncBlockReceived);
        let final_metrics = gather(&registry).unwrap();
        assert!(final_metrics.contains("blocks_received 3"));
    }

    #[tokio::test]
    async fn test_gather_metrics_returns_success_response() {
        let registry = Registry::new();
        let metrics = Metrics::new(&registry).unwrap();

        let (status, body) = gather_metrics(&registry).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("blocks_received 0"));
        assert!(body.contains("# HELP blocks_received"));
    }
}

use error_stack::{Result, ResultExt};
use prometheus::{Encoder, IntCounter, Registry, TextEncoder};

use crate::prometheus_metrics::msg::{MetricsError, MetricsMsg};

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
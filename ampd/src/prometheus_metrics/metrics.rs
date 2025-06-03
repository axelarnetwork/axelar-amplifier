use prometheus::{Encoder, IntCounter, Registry, TextEncoder};

use crate::prometheus_metrics::msg::{MetricsError, MetricsMsg};

pub struct Metrics {
    block_received: IntCounter,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Result<Self, MetricsError> {
        let block_received = IntCounter::new("blocks_received", "Number of blocks received")
            .map_err(|_| MetricsError::MetricSpawnFailed)?;

        registry
            .register(Box::new(block_received.clone()))
            .map_err(|_| MetricsError::MetricRegisterFailed)?;

        Ok(Self { block_received })
    }

    // modify metrics based on the message received
    pub fn handle_message(&self, msg: MetricsMsg) -> Result<(), MetricsError> {
        match msg {
            MetricsMsg::IncBlockReceived => {
                self.block_received.inc();
            }
        }
        Ok(())
    }
}

pub fn gather(registry: &Registry) -> Result<String, MetricsError> {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();

    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|_e| MetricsError::EncodeError)?;

    String::from_utf8(buffer).map_err(|_e| MetricsError::Utf8Error)
}

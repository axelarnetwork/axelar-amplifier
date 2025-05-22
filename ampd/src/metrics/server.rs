use prometheus::{Encoder, IntCounter, Registry, TextEncoder};
use tokio::sync::mpsc::Receiver;

use crate::metrics::msg::{MetricsError, MetricsMsg};

pub struct MetricsServer {
    registry: Registry,
    block_received: IntCounter,
}

impl MetricsServer {
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let block_received = IntCounter::new("blocks_received", "Number of blocks received")?;

        registry.register(Box::new(block_received.clone()))?;

        Ok(Self {
            registry,
            block_received,
        })
    }

    pub async fn run(&self, mut rx: Receiver<MetricsMsg>) {
        while let Some(msg) = rx.recv().await {
            match msg {
                MetricsMsg::IncBlockReceived => {
                    self.block_received.inc();
                }
            }
        }
    }

    pub fn gather(&self) -> Result<String, MetricsError> {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();

        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|_e| MetricsError::EncodeError)?;

        String::from_utf8(buffer).map_err(|_e| MetricsError::Utf8Error)
    }
}

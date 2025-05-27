use std::collections::HashMap;

use prometheus::{Encoder, IntCounter, Registry, TextEncoder};

use crate::metrics::msg::{MetricsError, MetricsMsg};

pub struct MetricsServer {
    registry: Registry,
    counters: HashMap<String, IntCounter>,
}

impl MetricsServer {
    pub fn new() -> Result<Self, MetricsError> {
        let registry = Registry::new();
        let mut counters = HashMap::new();

        let block_received = IntCounter::new("blocks_received", "Number of blocks received")
        .map_err(|_| MetricsError::MetricSpawnFailed)?;

        let timer = IntCounter::new("timer", "increase every 2 seconds")
        .map_err(|_| MetricsError::MetricSpawnFailed)?;

        registry.register(Box::new(block_received.clone()))
        .map_err(|_| MetricsError::MetricRegisterFailed)?;

        registry.register(Box::new(timer.clone()))
        .map_err(|_| MetricsError::MetricRegisterFailed)?;

        counters.insert("blocks_received".to_string(), block_received);
        counters.insert("timer".to_string(), timer);

        Ok(Self {
            registry,
            counters,
        })
    }

    pub fn handle_message(&mut self, msg: MetricsMsg) -> Result<(), MetricsError> {
        match msg {
            MetricsMsg::IncBlockReceived => {
                self.counters
                    .get_mut("blocks_received")
                    .ok_or_else(|| MetricsError::CounterNotFound("blocks_received".to_string()))?
                    .inc();
            }
            MetricsMsg::IncTimer => {
                self.counters
                    .get_mut("timer")
                    .ok_or_else(|| MetricsError::CounterNotFound("timer".to_string()))?
                    .inc();
            }
        }
        Ok(())
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

use std::time::Duration;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use sysinfo::{System, Pid, RefreshKind, ProcessToUpdate, ProcessRefreshKind};
use error_stack::Result;

use crate::monitoring::server::MonitoringClient;
use crate::monitoring::endpoints::metrics::{MetricsMsg, MetricsError};

pub struct SystemMetricsCollector {
    system: System,                    
    pid: Pid,                         
    monitoring_client: MonitoringClient,
    collection_interval: Duration,
}

impl SystemMetricsCollector {
    pub fn new(monitoring_client: MonitoringClient, collection_interval: Duration) -> Self {
        let system = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(true)
                .with_memory(true)
                .with_cpu(true),
        );
        let pid = Pid::from_u32(std::process::id());

        Self {
            system,
            pid,
            monitoring_client,
            collection_interval,
        }
    }

    pub async fn run(mut self, cancel: CancellationToken) -> Result<(), MetricsError> {
        let mut interval = interval(self.collection_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Refresh system info (mutable operation)
                    self.system.refresh_processes_specifics(
                        ProcessToUpdate::Some(&[self.pid]),
                        true,
                        ProcessRefreshKind::nothing().with_cpu().with_memory(),
                    );

                    // Get metrics and send to monitoring system
                    if let Some(process) = self.system.process(self.pid) {
                        let cpu_usage = process.cpu_usage() as f64;
                        let memory_usage = process.memory();

                        // Send via message (no shared state issues)
                        if let Err(e) = self.monitoring_client.record_metric(
                            MetricsMsg::SetSystemMetrics { cpu_usage, memory_usage }
                        ) {
                            tracing::warn!("Failed to record system metrics: {:?}", e);
                        }
                    }
                }
                _ = cancel.cancelled() => {
                    tracing::info!("System metrics collector shutting down");
                    break;
                }
            }
        }
        Ok(())
    }
} 
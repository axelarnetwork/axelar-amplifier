use std::time::Duration;

use error_stack::Result;
use sysinfo::{get_current_pid, Pid, ProcessRefreshKind, RefreshKind, System};
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

use crate::monitoring::endpoints::metrics::{MetricsError, MetricsMsg};
use crate::monitoring::server::MonitoringClient;

pub struct SystemMetricsCollector {
    system: System,
    pid: Pid,
    collection_interval: Duration,
    monitoring_client: MonitoringClient,
}

impl SystemMetricsCollector {
    pub fn new(collection_interval: Duration, monitoring_client: MonitoringClient) -> Result<Self, MetricsError> {
        let system = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new().with_cpu().with_memory()),
        );

        let pid = get_current_pid().map_err(|_| MetricsError::MetricSpawnFailed)?;

        Ok(Self {
            system,
            pid,
            collection_interval,
            monitoring_client,
        })
    }

    pub async fn run(
        mut self,
        cancel: CancellationToken
    ) -> Result<(), MetricsError> {
        let mut interval = interval(self.collection_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    self.system.refresh_processes_specifics(
                        ProcessRefreshKind::new().with_cpu().with_memory(),
                    );

                    match self.system.process(self.pid) {
                        Some(process) => {
                            let cpu_usage = process.cpu_usage();
                            let memory_usage = process.memory();

                            if let Err(e) = self.monitoring_client.record_metric(
                                MetricsMsg::SetSystemMetrics { cpu_usage, memory_usage }
                            ) {
                                tracing::warn!(
                                    error = %e,
                                    "Failed to record system metrics");
                            }
                        }
                        None => {
                            tracing::warn!("Failed to get process metrics");
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

#[cfg(test)]
mod tests {
    use reqwest::{StatusCode, Url};
    use tokio::sync::mpsc;

    use super::*;
    use crate::monitoring::server::test_utils::test_monitoring_server_setup;
    use crate::monitoring::server::MonitoringClient;

    fn get_metric(metrics: &str, name: &str) -> Option<f64> {
        metrics
            .lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<f64>().ok())
    }

    #[tokio::test(start_paused = true)]
    async fn test_system_metrics_collector_tracks_cpu_and_memory_correctly() {
        let (bind_address, server, client, cancel) = test_monitoring_server_setup();
        let collector = SystemMetricsCollector::new(Duration::from_millis(100), client.clone())
            .expect("Failed to create SystemMetricsCollector");


        let collector_cancel1 = cancel.clone();
        let collector_cancel2 = cancel.clone();

        tokio::spawn(async move { collector.run(collector_cancel1).await });
        tokio::spawn(async move { server.run(collector_cancel2).await });

        tokio::time::sleep(Duration::from_millis(250)).await;

        let base_url = Url::parse(&format!("http://{}", bind_address.unwrap())).unwrap();
        let url = base_url.join("metrics").unwrap();
        let response = reqwest::get(url).await.unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let metrics_text = response.text().await.unwrap();
        let cpu_usage = get_metric(&metrics_text, "ampd_cpu_usage_percent").unwrap();
        let memory_usage = get_metric(&metrics_text, "ampd_memory_usage_bytes").unwrap();

        assert!(cpu_usage > 0.0);
        assert!(memory_usage > 0.0);

        cancel.cancel();
    }
}

use axum::http::StatusCode;
use error_stack::{Result, ResultExt};
use prometheus::{Encoder, GaugeVec, IntCounter, IntCounterVec, Opts, Registry, TextEncoder};
use thiserror::Error;

#[derive(Clone)]
pub enum MetricsMsg {
    IncBlockReceived,
}

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
}

pub struct Metrics {
    block_received: IntCounter,
    verifier_votes_casted_successful: IntCounterVec,
    verifier_votes_casted_failed: IntCounterVec,
    verifier_votes_casted_success_rate: GaugeVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Result<Self, MetricsError> {
        let block_received = IntCounter::new("blocks_received", "number of blocks received")
            .change_context(MetricsError::MetricSpawnFailed)?;

        let (
            verifier_votes_casted_successful,
            verifier_votes_casted_failed,
            verifier_votes_casted_success_rate,
        ) = Self::create_verifier_votes_casted_metrics()?;

        registry
            .register(Box::new(block_received.clone()))
            .change_context(MetricsError::MetricRegisterFailed)?;

        Self::register_metrics(
            registry,
            &verifier_votes_casted_successful,
            &verifier_votes_casted_failed,
            &verifier_votes_casted_success_rate,
        )?;

        Ok(Self {
            block_received,
            verifier_votes_casted_successful,
            verifier_votes_casted_failed,
            verifier_votes_casted_success_rate,
        })
    }

    fn create_verifier_votes_casted_metrics(
    ) -> Result<(IntCounterVec, IntCounterVec, GaugeVec), MetricsError> {
        let verifier_votes_casted_successful = IntCounterVec::new(
            Opts::new(
                "verifier_votes_casted_successful",
                "number of successful votes casted",
            )
            .variable_labels(vec!["verifier_id".to_string(), "chain_name".to_string()]),
            &["verifier_id", "chain_name"],
        )
        .change_context(MetricsError::MetricSpawnFailed)?;

        let verifier_votes_casted_failed = IntCounterVec::new(
            Opts::new(
                "verifier_votes_casted_failed",
                "number of failed votes casted",
            )
            .variable_labels(vec!["verifier_id".to_string(), "chain_name".to_string()]),
            &["verifier_id", "chain_name"],
        )
        .change_context(MetricsError::MetricSpawnFailed)?;

        let verifier_votes_casted_success_rate = GaugeVec::new(
            Opts::new(
                "verifier_votes_casted_success_rate",
                "success rate of votes casted",
            )
            .variable_labels(vec!["verifier_id".to_string(), "chain_name".to_string()]),
            &["verifier_id", "chain_name"],
        )
        .change_context(MetricsError::MetricSpawnFailed)?;

        Ok((
            verifier_votes_casted_successful,
            verifier_votes_casted_failed,
            verifier_votes_casted_success_rate,
        ))
    }

    fn register_metrics(
        registry: &Registry,
        verifier_votes_casted_successful: &IntCounterVec,
        verifier_votes_casted_failed: &IntCounterVec,
        verifier_votes_casted_success_rate: &GaugeVec,
    ) -> Result<(), MetricsError> {
        registry
            .register(Box::new(verifier_votes_casted_successful.clone()))
            .change_context(MetricsError::MetricRegisterFailed)?;

        registry
            .register(Box::new(verifier_votes_casted_failed.clone()))
            .change_context(MetricsError::MetricRegisterFailed)?;

        registry
            .register(Box::new(verifier_votes_casted_success_rate.clone()))
            .change_context(MetricsError::MetricRegisterFailed)?;

        Ok(())
    }

    pub fn handle_message(&self, msg: MetricsMsg) {
        match msg {
            MetricsMsg::IncBlockReceived => {
                self.block_received.inc();
            }
            MetricsMsg::IncSuccessVoteCasted {
                verifier_id,
                chain_name,
            } => {
                self.verifier_votes_casted_successful
                    .with_label_values(&[&verifier_id, &chain_name])
                    .inc();
                self.update_success_rate(&verifier_id, &chain_name);
            }
            MetricsMsg::IncFailedVoteCasted {
                verifier_id,
                chain_name,
            } => {
                self.verifier_votes_casted_failed
                    .with_label_values(&[&verifier_id, &chain_name])
                    .inc();
                self.update_success_rate(&verifier_id, &chain_name);
            }
        }
    }

    fn update_success_rate(&self, verifier_id: &str, chain_name: &str) {
        let successful_casted_votes = self
            .verifier_votes_casted_successful
            .with_label_values(&[verifier_id, chain_name])
            .get();

        let failed_casted_votes = self
            .verifier_votes_casted_failed
            .with_label_values(&[verifier_id, chain_name])
            .get();

        let total_casted_votes = successful_casted_votes + failed_casted_votes;

        let success_rate = match total_casted_votes {
            0 => 0.0,
            _ => successful_casted_votes as f64 / total_casted_votes as f64,
        };

        self.verifier_votes_casted_success_rate
            .with_label_values(&[verifier_id, chain_name])
            .set(success_rate);
    }
}

<<<<<<< HEAD

pub async fn gather_metrics(registry: &Registry) -> (StatusCode, String) {
<<<<<<< HEAD
    match render_metrics(registry) {
=======
    match gather(registry) {
>>>>>>> 94bcfc7d (update style)
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

<<<<<<< HEAD
fn render_metrics(registry: &Registry) -> Result<String, MetricsError> {
=======
fn gather(registry: &Registry) -> Result<String, MetricsError> {
>>>>>>> 94bcfc7d (update style)
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();

    encoder
        .encode(&metric_families, &mut buffer)
        .change_context(MetricsError::EncodeError)?;

    String::from_utf8(buffer).change_context(MetricsError::Utf8Error)
}

#[cfg(test)]
mod tests {
    use prometheus::Registry;

    use super::*;

    #[test]
    fn metrics_handle_message_increments_block_received_counter_successfully() {
        let registry = Registry::new();
        let metrics = Metrics::new(&registry).unwrap();

        let initial_metrics = render_metrics(&registry).unwrap();
        assert!(initial_metrics.contains("blocks_received 0"));

        metrics.handle_message(MetricsMsg::IncBlockReceived);
        metrics.handle_message(MetricsMsg::IncBlockReceived);
        metrics.handle_message(MetricsMsg::IncBlockReceived);
        let final_metrics = render_metrics(&registry).unwrap();
        assert!(final_metrics.contains("blocks_received 3"));
    }

    #[test]
    fn metrics_handle_all_votes_casted_related_messages_successfully() {
        let registry = Registry::new();
        let metrics = Metrics::new(&registry).unwrap();
        for _ in 0..2 {
            metrics.handle_message(MetricsMsg::IncSuccessVoteCasted {
                verifier_id: "axelar1abc".to_string(),
                chain_name: "ethereum".to_string(),
            });
        }

        metrics.handle_message(MetricsMsg::IncFailedVoteCasted {
            verifier_id: "axelar1abc".to_string(),
            chain_name: "ethereum".to_string(),
        });

        let final_metrics = gather(&registry).unwrap();

        assert!(final_metrics.contains("verifier_votes_casted_successful{chain_name=\"ethereum\",verifier_id=\"axelar1abc\"} 2"));
        assert!(final_metrics.contains(
            "verifier_votes_casted_failed{chain_name=\"ethereum\",verifier_id=\"axelar1abc\"} 1"
        ));
        assert!(final_metrics.contains("verifier_votes_casted_success_rate{chain_name=\"ethereum\",verifier_id=\"axelar1abc\"} 0.6666666666666666"));
    }

    #[tokio::test]
    async fn test_gather_metrics_returns_success_response() {
        let registry = Registry::new();
        let _ = Metrics::new(&registry).unwrap();

        let (status, body) = gather_metrics(&registry).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("blocks_received 0"));
        assert!(body.contains("# HELP blocks_received"));
    }
}

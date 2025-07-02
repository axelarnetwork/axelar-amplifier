use axum::http::StatusCode;
use error_stack::{ensure, Result, ResultExt};
use prometheus::{Encoder, GaugeVec, IntCounter, IntCounterVec, Opts, Registry, TextEncoder};
use thiserror::Error;

#[derive(Clone)]
pub enum MetricsMsg {
    IncBlockReceived,
    IncSuccessVoteCasted {
        verifier_id: String,
        chain_name: String,
    },
    IncFailedVoteCasted {
        verifier_id: String,
        chain_name: String,
    },
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
    #[error("metric value overflow, value is larger than 1.7976931348623157e+308")]
    MetricValueOverflow,
    #[error("no vote is recorded but success rate is updated")]
    InvalidVoteMetricsUpdate,
}

pub struct Metrics {
    block_received: BlockReceivedMetrics,
    votes_casted: VotesCastedMetrics,
}

struct BlockReceivedMetrics {
    total: IntCounter,
}

struct VotesCastedMetrics {
    succeed: IntCounterVec,
    failed: IntCounterVec,
    success_rate: GaugeVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Result<Self, MetricsError> {
        let block_received = BlockReceivedMetrics::new()?;
        let votes_casted = VotesCastedMetrics::new()?;

        block_received.register(registry)?;
        votes_casted.register(registry)?;

        Ok(Self {
            block_received,
            votes_casted,
        })
    }

    pub fn handle_message(&self, msg: MetricsMsg) -> Result<(), MetricsError> {
        match msg {
            MetricsMsg::IncBlockReceived => {
                self.block_received.increment()?;
            }
            MetricsMsg::IncSuccessVoteCasted {
                verifier_id,
                chain_name,
            } => {
                self.votes_casted
                    .record_success(&verifier_id, &chain_name)?;
            }
            MetricsMsg::IncFailedVoteCasted {
                verifier_id,
                chain_name,
            } => {
                self.votes_casted
                    .record_failure(&verifier_id, &chain_name)?;
            }
        }
        Ok(())
    }
}

impl BlockReceivedMetrics {
    fn new() -> Result<Self, MetricsError> {
        let counter = IntCounter::new("blocks_received", "number of blocks received")
            .change_context(MetricsError::MetricSpawnFailed)?;
        Ok(Self { total: counter })
    }

    fn register(&self, registry: &Registry) -> Result<(), MetricsError> {
        registry
            .register(Box::new(self.total.clone()))
            .change_context(MetricsError::MetricRegisterFailed)?;
        Ok(())
    }

    fn increment(&self) -> Result<(), MetricsError> {
        let current_value = self.total.get();
        ensure!(current_value < u64::MAX, MetricsError::MetricValueOverflow);
        self.total.inc();
        Ok(())
    }
}

impl VotesCastedMetrics {
    fn new() -> Result<Self, MetricsError> {
        let (succeed, failed, success_rate) = create_verifier_votes_casted_metrics()?;
        Ok(Self {
            succeed,
            failed,
            success_rate,
        })
    }

    fn register(&self, registry: &Registry) -> Result<(), MetricsError> {
        registry
            .register(Box::new(self.succeed.clone()))
            .change_context(MetricsError::MetricRegisterFailed)?;

        registry
            .register(Box::new(self.failed.clone()))
            .change_context(MetricsError::MetricRegisterFailed)?;

        registry
            .register(Box::new(self.success_rate.clone()))
            .change_context(MetricsError::MetricRegisterFailed)?;

        Ok(())
    }

    fn record_success(&self, verifier_id: &str, chain_name: &str) -> Result<(), MetricsError> {
        let current_value = self
            .succeed
            .with_label_values(&[verifier_id, chain_name])
            .get();
        ensure!(current_value < u64::MAX, MetricsError::MetricValueOverflow);

        self.succeed
            .with_label_values(&[verifier_id, chain_name])
            .inc();
        self.update_success_rate(verifier_id, chain_name)?;
        Ok(())
    }

    fn record_failure(&self, verifier_id: &str, chain_name: &str) -> Result<(), MetricsError> {
        let current_value = self
            .failed
            .with_label_values(&[verifier_id, chain_name])
            .get();
        ensure!(current_value < u64::MAX, MetricsError::MetricValueOverflow);

        self.failed
            .with_label_values(&[verifier_id, chain_name])
            .inc();
        self.update_success_rate(verifier_id, chain_name)?;
        Ok(())
    }

    fn update_success_rate(&self, verifier_id: &str, chain_name: &str) -> Result<(), MetricsError> {
        let successful_votes = self
            .succeed
            .with_label_values(&[verifier_id, chain_name])
            .get();

        let failed_votes = self
            .failed
            .with_label_values(&[verifier_id, chain_name])
            .get();

        let total_votes = successful_votes
            .checked_add(failed_votes)
            .ok_or(MetricsError::MetricValueOverflow)?;

        let success_rate = match total_votes {
            0 => {
                return Err(MetricsError::InvalidVoteMetricsUpdate.into());
            }
            _ => successful_votes as f64 / total_votes as f64,
        };

        self.success_rate
            .with_label_values(&[verifier_id, chain_name])
            .set(success_rate);
        Ok(())
    }
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

        metrics
            .handle_message(MetricsMsg::IncBlockReceived)
            .expect("handle message should not fail");
        metrics
            .handle_message(MetricsMsg::IncBlockReceived)
            .expect("handle message should not fail");
        metrics
            .handle_message(MetricsMsg::IncBlockReceived)
            .expect("handle message should not fail");
        let final_metrics = render_metrics(&registry).unwrap();
        assert!(final_metrics.contains("blocks_received 3"));
    }

    #[test]
    fn metrics_handle_all_votes_casted_related_messages_successfully() {
        let registry = Registry::new();
        let metrics = Metrics::new(&registry).unwrap();
        for _ in 0..2 {
            metrics
                .handle_message(MetricsMsg::IncSuccessVoteCasted {
                    verifier_id: "axelar1abc".to_string(),
                    chain_name: "ethereum".to_string(),
                })
                .expect("handle message should not fail");
        }

        metrics
            .handle_message(MetricsMsg::IncFailedVoteCasted {
                verifier_id: "axelar1abc".to_string(),
                chain_name: "ethereum".to_string(),
            })
            .expect("handle message should not fail");

        let final_metrics = render_metrics(&registry).unwrap();

        assert!(final_metrics.contains("verifier_votes_casted_successful{chain_name=\"ethereum\",verifier_id=\"axelar1abc\"} 2"));
        assert!(final_metrics.contains(
            "verifier_votes_casted_failed{chain_name=\"ethereum\",verifier_id=\"axelar1abc\"} 1"
        ));
        assert!(final_metrics.contains("verifier_votes_casted_success_rate{chain_name=\"ethereum\",verifier_id=\"axelar1abc\"} 0.6666666666666666"));
    }

    #[test]
    fn metrics_handle_message_fails_on_overflow() {
        let registry = Registry::new();
        let metrics = Metrics::new(&registry).unwrap();
        metrics.block_received.total.inc_by(u64::MAX);
        let result = metrics.handle_message(MetricsMsg::IncBlockReceived);
        assert!(result.is_err(), "should fail on overfow ");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("metric value overflow"));
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

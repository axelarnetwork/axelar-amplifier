use tokio::sync::mpsc::Sender;
use error_stack::{Result, ResultExt};
use crate::prometheus_metrics::msg::{MetricsError, MetricsMsg};

#[derive(Clone)]
pub struct MetricsClient {
    sender: Sender<MetricsMsg>,
}

impl MetricsClient {
    pub fn new(sender: Sender<MetricsMsg>) -> Self {
        Self { sender }
    }

    pub fn record_metric(&self, msg: MetricsMsg) -> Result<(), MetricsError> {
        self.sender
            .try_send(msg)
            .change_context(MetricsError::MetricUpdateFailed)?;
        Ok(())
    }
}

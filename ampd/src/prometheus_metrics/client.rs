use tokio::sync::mpsc::Sender;

use crate::prometheus_metrics::msg::{MetricsError, MetricsMsg};

#[derive(Clone)]
pub struct MetricsClient {
    sender: Sender<MetricsMsg>,
}

impl MetricsClient {
    pub fn new(sender: Sender<MetricsMsg>) -> Self {
        Self { sender }
    }

    pub fn send_metrics_msg(&self, msg: MetricsMsg) -> Result<(), MetricsError> {
        self.sender
            .try_send(msg)
            .map_err(|_| MetricsError::MetricUpdateFailed)?;
        Ok(())
    }
}

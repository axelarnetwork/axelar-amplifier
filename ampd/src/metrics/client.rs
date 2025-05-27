use tokio::sync::mpsc::Sender;
use crate::metrics::msg::MetricsError;

use crate::metrics::msg::MetricsMsg;

#[derive(Clone)]
pub struct MetricsClient {
    sender: Sender<MetricsMsg>,
}

impl MetricsClient {
    pub fn new(sender: Sender<MetricsMsg>) -> Self {
        Self { sender }
    }

    pub fn inc_block_received(&self) -> Result<(), MetricsError> {
        self.sender.try_send(MetricsMsg::IncBlockReceived)
            .map_err(|_| MetricsError::MetricUpdateFailed)?;
        Ok(())
    }
    pub fn inc_timer(&self) -> Result<(), MetricsError> {
        self.sender.try_send(MetricsMsg::IncTimer)
            .map_err(|_| MetricsError::MetricUpdateFailed)?;
        Ok(())
    }
}

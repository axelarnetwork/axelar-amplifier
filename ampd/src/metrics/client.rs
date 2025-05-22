use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;

use crate::metrics::msg::MetricsMsg;

#[derive(Clone)]
pub struct MetricsClient {
    sender: Sender<MetricsMsg>,
}

impl MetricsClient {
    pub fn new(sender: Sender<MetricsMsg>) -> Self {
        Self { sender }
    }

    pub fn inc_block_received(&self) -> Result<(), TrySendError<MetricsMsg>> {
        self.sender.try_send(MetricsMsg::IncBlockReceived)
    }
}

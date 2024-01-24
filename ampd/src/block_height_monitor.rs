use error_stack::{Result, ResultExt};
use std::time::Duration;
use thiserror::Error;
use tokio::{
    select,
    sync::watch::{self, Receiver, Sender},
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::tm_client::TmClient;

pub struct BlockHeightMonitor<T: TmClient + Sync> {
    latest_height_tx: Sender<u64>,
    latest_height_rx: Receiver<u64>,
    client: T,
    poll_interval: Duration,
}

#[derive(Error, Debug)]
pub enum BlockHeightMonitorError {
    #[error("failed to get latest block")]
    LatestBlock,
}

impl<T: TmClient + Sync> BlockHeightMonitor<T> {
    pub async fn connect(client: T) -> Result<Self, BlockHeightMonitorError> {
        let latest_block = client
            .latest_block()
            .await
            .change_context(BlockHeightMonitorError::LatestBlock)?;
        let (latest_height_tx, latest_height_rx) =
            watch::channel(latest_block.block.header.height.into());
        Ok(Self {
            latest_height_tx,
            latest_height_rx,
            client,
            poll_interval: Duration::new(3, 0),
        })
    }

    #[allow(dead_code)]
    pub fn poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    pub async fn run(self, token: CancellationToken) -> Result<(), BlockHeightMonitorError> {
        let mut interval = time::interval(self.poll_interval);

        loop {
            select! {
                _ = interval.tick() => {
                    let latest_block = self.client.latest_block().await.change_context(BlockHeightMonitorError::LatestBlock)?;

                    // expect is ok here, because the latest_height_rx receiver is never closed, and thus the channel should always be open
                    self.latest_height_tx.send(latest_block.block.header.height.into()).expect("failed to publish latest block height");
                },
                _ = token.cancelled() => {
                    info!("block height monitor exiting");

                    return Ok(())
                },
            }
        }
    }

    #[allow(dead_code)]
    pub fn latest_block_height(&self) -> Receiver<u64> {
        self.latest_height_rx.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::time::Duration;

    use mockall::mock;
    use tendermint::block::Height;
    use tokio::test;
    use tokio::time;
    use tokio_util::sync::CancellationToken;

    use crate::tm_client;

    use crate::BlockHeightMonitor;
    use async_trait::async_trait;

    #[test]
    async fn latest_block_height_should_work() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("tests/axelar_block.json")).unwrap();
        let mut height = u64::from(block.header.height);

        let mut mock_client = MockTmClientClonable::new();
        mock_client.expect_latest_block().returning(move || {
            let mut block = block.clone();
            height += 1;
            block.header.height = height.try_into().unwrap();
            Ok(tm_client::BlockResponse {
                block_id: Default::default(),
                block,
            })
        });
        let mock_client_2 = MockTmClientClonable::new();
        mock_client
            .expect_clone()
            .return_once(move || mock_client_2);

        let token = CancellationToken::new();
        let poll_interval = Duration::new(0, 1e7 as u32);
        let monitor = BlockHeightMonitor::connect(mock_client)
            .await
            .unwrap()
            .poll_interval(poll_interval.clone());
        let exit_token = token.clone();

        let latest_block_height = monitor.latest_block_height();
        let handle = tokio::spawn(async move { monitor.run(exit_token).await });

        let mut prev_height = latest_block_height.borrow().clone();
        for _ in 1..10 {
            time::sleep(poll_interval * 2).await;
            let next_height = latest_block_height.borrow().clone();
            assert!(next_height > prev_height);
            prev_height = next_height;
        }

        token.cancel();

        assert!(handle.await.is_ok());
    }

    type BlockResultsResponse = tendermint_rpc::endpoint::block_results::Response;
    type BlockResponse = tendermint_rpc::endpoint::block::Response;
    type Error = tendermint_rpc::Error;

    use error_stack::Result;
    mock! {
        TmClientClonable {}

        #[async_trait]
        impl tm_client::TmClient for TmClientClonable {
            async fn latest_block(&self) -> Result<BlockResponse, Error>;
            async fn block_results(&self, block_height: Height) -> Result<BlockResultsResponse, Error>;
        }

        impl Clone for TmClientClonable {
            fn clone(&self) -> Self;
        }
    }
}

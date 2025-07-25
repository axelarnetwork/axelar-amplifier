use std::time::Duration;

use async_trait::async_trait;
use error_stack::{Report, Result};
use mockall::automock;
use tendermint::block::Height;
use tendermint_rpc::{Client, HttpClient};

use crate::asyncutil::future::{self, RetryPolicy};

pub type BlockResultsResponse = tendermint_rpc::endpoint::block_results::Response;
pub type BlockResponse = tendermint_rpc::endpoint::block::Response;
pub type Error = tendermint_rpc::Error;

const MAX_RETRIES: u64 = 15;
const RETRY_DELAY: Duration = Duration::from_secs(1);

#[automock]
#[async_trait]
pub trait TmClient {
    async fn latest_block(&self) -> Result<BlockResponse, Error>;
    async fn block_results(&self, block_height: Height) -> Result<BlockResultsResponse, Error>;
}

#[async_trait]
impl TmClient for HttpClient {
    async fn latest_block(&self) -> Result<BlockResponse, Error> {
        future::with_retry(
            || Client::latest_block(self),
            RetryPolicy::repeat_constant(RETRY_DELAY, MAX_RETRIES),
        )
        .await
        .map_err(Report::from)
    }

    async fn block_results(&self, height: Height) -> Result<BlockResultsResponse, Error> {
        future::with_retry(
            || Client::block_results(self, height),
            RetryPolicy::repeat_constant(RETRY_DELAY, MAX_RETRIES),
        )
        .await
        .map_err(Report::from)
    }
}

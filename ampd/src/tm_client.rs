use std::time::Duration;

use async_trait::async_trait;
use error_stack::{Report, Result};
use mockall::automock;
use serde::{Deserialize, Serialize};
use tendermint::block::Height;
use tendermint_rpc::{Client, HttpClient};

use crate::asyncutil::future::{self, RetryPolicy};

pub type BlockResultsResponse = tendermint_rpc::endpoint::block_results::Response;
pub type BlockResponse = tendermint_rpc::endpoint::block::Response;
pub type Error = tendermint_rpc::Error;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Config {
    pub max_retries: u64,
    #[serde(with = "humantime_serde")]
    pub retry_delay: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_retries: 15,
            retry_delay: Duration::from_secs(1),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TendermintClient {
    client: HttpClient,
    retry_policy: RetryPolicy,
}

impl TendermintClient {
    pub fn new(client: HttpClient, max_retries: u64, retry_delay: Duration) -> Self {
        let retry_policy = RetryPolicy::repeat_constant(retry_delay, max_retries);
        Self {
            client,
            retry_policy,
        }
    }
}

#[automock]
#[async_trait]
pub trait TmClient {
    async fn latest_block(&self) -> Result<BlockResponse, Error>;
    async fn block_results(&self, block_height: Height) -> Result<BlockResultsResponse, Error>;
}

#[async_trait]
impl TmClient for TendermintClient {
    async fn latest_block(&self) -> Result<BlockResponse, Error> {
        future::with_retry(|| Client::latest_block(&self.client), self.retry_policy)
            .await
            .map_err(Report::from)
    }

    async fn block_results(&self, height: Height) -> Result<BlockResultsResponse, Error> {
        future::with_retry(
            || Client::block_results(&self.client, height),
            self.retry_policy,
        )
        .await
        .map_err(Report::from)
    }
}

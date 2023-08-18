use async_trait::async_trait;
use error_stack::{IntoReport, Result};
use mockall::automock;
use tendermint::block::Height;
use tendermint_rpc::{Client, HttpClient};

pub type BlockResultsResponse = tendermint_rpc::endpoint::block_results::Response;
pub type BlockResponse = tendermint_rpc::endpoint::block::Response;
pub type Error = tendermint_rpc::Error;

#[automock]
#[async_trait]
pub trait TmClient {
    async fn latest_block(&self) -> Result<BlockResponse, Error>;
    async fn block_results(&self, block_height: Height) -> Result<BlockResultsResponse, Error>;
}

#[async_trait]
impl TmClient for HttpClient {
    async fn latest_block(&self) -> Result<BlockResponse, Error> {
        Client::latest_block(self).await.into_report()
    }

    async fn block_results(&self, height: Height) -> Result<BlockResultsResponse, Error> {
        Client::block_results(self, height).await.into_report()
    }
}

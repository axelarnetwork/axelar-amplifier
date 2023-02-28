use crate::url::Url;
use async_trait::async_trait;
use error_stack::{self, IntoReport};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::Error;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use mockall::automock;
use web3::types::{BlockHeader, TransactionReceipt, H256, U64};

type Result<T> = error_stack::Result<T, Error>;

#[automock]
#[async_trait]
pub trait EthereumClient {
    async fn block_number(&self) -> Result<U64>;
    async fn transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>>;
    #[allow(dead_code)]
    async fn block_header<T>(&self, number: T) -> Result<Option<BlockHeader>>
    where
        T: Into<U64> + Send + Sync + 'static;
}

#[async_trait]
pub trait MoonbeamClient: EthereumClient {
    async fn finalized_block_hash(&self) -> Result<H256>;
}

pub struct Client<C>
where
    C: ClientT,
{
    client: C,
}

impl<C> Client<C>
where
    C: ClientT,
{
    pub fn new(client: C) -> Self {
        Client { client }
    }
}

impl Client<HttpClient> {
    pub fn new_http(target: &Url) -> Result<Self> {
        let http_client = HttpClientBuilder::default().build(target.as_str()).into_report()?;
        Ok(Client::new(http_client))
    }
}

#[async_trait]
impl<C> EthereumClient for Client<C>
where
    C: ClientT + Send + Sync + 'static,
{
    async fn block_number(&self) -> Result<U64> {
        self.client
            .request("eth_blockNumber", rpc_params![])
            .await
            .into_report()
    }

    async fn transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>> {
        self.client
            .request("eth_getTransactionReceipt", rpc_params![hash])
            .await
            .into_report()
    }

    async fn block_header<T>(&self, number: T) -> Result<Option<BlockHeader>>
    where
        T: Into<U64> + Send + Sync,
    {
        self.client
            .request("eth_getBlockByNumber", rpc_params![number.into(), false])
            .await
            .into_report()
    }
}

#[async_trait]
impl<C> MoonbeamClient for Client<C>
where
    C: ClientT + Send + Sync + 'static,
{
    async fn finalized_block_hash(&self) -> Result<H256> {
        self.client
            .request("chain_getFinalizedHead", rpc_params![])
            .await
            .into_report()
    }
}

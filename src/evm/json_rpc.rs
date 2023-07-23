use crate::url::Url;
use async_trait::async_trait;
use error_stack::{self, IntoReport};
use ethers::providers::{Http, JsonRpcClient, ProviderError};
use ethers::types::{TransactionReceipt, H256, U64};
use mockall::automock;

type Result<T> = error_stack::Result<T, ProviderError>;

#[automock]
#[async_trait]
pub trait EthereumClient {
    async fn block_number(&self) -> Result<U64>;
    async fn transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>>;
}

#[async_trait]
pub trait MoonbeamClient: EthereumClient {
    async fn finalized_block_hash(&self) -> Result<H256>;
}

pub struct Client<P>
where
    P: JsonRpcClient,
{
    provider: P,
}

impl<P> Client<P>
where
    P: JsonRpcClient,
{
    pub fn new(provider: P) -> Self {
        Client { provider }
    }
}

impl Client<Http> {
    pub fn new_http(url: &Url) -> Result<Self> {
        Ok(Client::new(Http::new(url)))
    }
}

#[async_trait]
impl<P> EthereumClient for Client<P>
where
    P: JsonRpcClient + Send + Sync + 'static,
{
    async fn block_number(&self) -> Result<U64> {
        self.provider
            .request("eth_blockNumber", ())
            .await
            .map_err(Into::into)
            .into_report()
    }

    async fn transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>> {
        self.provider
            .request("eth_getTransactionReceipt", [hash])
            .await
            .map_err(Into::into)
            .into_report()
    }
}

#[async_trait]
impl<P> MoonbeamClient for Client<P>
where
    P: JsonRpcClient + Send + Sync + 'static,
{
    async fn finalized_block_hash(&self) -> Result<H256> {
        self.provider
            .request("chain_getFinalizedHead", ())
            .await
            .map_err(Into::into)
            .into_report()
    }
}

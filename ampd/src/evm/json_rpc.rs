use async_trait::async_trait;
use ethers::providers::{JsonRpcClient, ProviderError};
use ethers::types::{Block, BlockNumber, TransactionReceipt, H256, U64};
use ethers::utils::serialize;
use mockall::automock;

use crate::json_rpc::Client;
use crate::types::Hash;

type Result<T> = error_stack::Result<T, ProviderError>;

#[automock]
#[async_trait]
pub trait EthereumClient {
    async fn finalized_block(&self) -> Result<Block<Hash>>;
    async fn block_number(&self) -> Result<U64>;
    async fn transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>>;
}

#[async_trait]
pub trait MoonbeamClient: EthereumClient {
    async fn finalized_block_hash(&self) -> Result<H256>;
}
#[async_trait]
impl<P> EthereumClient for Client<P>
where
    P: JsonRpcClient + Send + Sync + 'static,
{
    async fn finalized_block(&self) -> Result<Block<Hash>> {
        self.request(
            "eth_getBlockByNumber",
            [serialize(&BlockNumber::Finalized), serialize(&false)],
        )
        .await
    }

    async fn block_number(&self) -> Result<U64> {
        self.request("eth_blockNumber", ()).await
    }

    async fn transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>> {
        self.request("eth_getTransactionReceipt", [hash]).await
    }
}

#[async_trait]
impl<P> MoonbeamClient for Client<P>
where
    P: JsonRpcClient + Send + Sync + 'static,
{
    async fn finalized_block_hash(&self) -> Result<H256> {
        self.request("chain_getFinalizedHead", ()).await
    }
}

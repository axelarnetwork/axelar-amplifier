use async_trait::async_trait;
use error_stack::Report;
use ethers::providers::{JsonRpcClient, ProviderError};
use sui_json_rpc_types::{SuiTransactionBlockResponse, SuiTransactionBlockResponseOptions};
use sui_types::digests::TransactionDigest;

use crate::evm::json_rpc::Client;

type Result<T> = error_stack::Result<T, ProviderError>;

#[async_trait]
pub trait SuiClient {
    async fn transaction_blocks(
        &self,
        digests: Vec<TransactionDigest>,
    ) -> Result<Vec<SuiTransactionBlockResponse>>;
}

#[async_trait]
impl<P> SuiClient for Client<P>
where
    P: JsonRpcClient + Send + Sync + 'static,
{
    async fn transaction_blocks(
        &self,
        digests: Vec<TransactionDigest>,
    ) -> Result<Vec<SuiTransactionBlockResponse>> {
        self.provider
            .request(
                "sui_multiGetTransactionBlocks",
                (
                    digests
                        .iter()
                        .map(|d| d.base58_encode())
                        .collect::<Vec<_>>(),
                    SuiTransactionBlockResponseOptions::new().with_events(),
                ),
            )
            .await
            .map_err(Into::into)
            .map_err(Report::from)
    }
}

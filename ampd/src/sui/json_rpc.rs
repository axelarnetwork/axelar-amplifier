use std::collections::HashSet;

use async_trait::async_trait;
use ethers::providers::{JsonRpcClient, ProviderError};
use mockall::automock;
use sui_json_rpc_types::{SuiTransactionBlockResponse, SuiTransactionBlockResponseOptions};
use sui_types::digests::TransactionDigest;

use crate::json_rpc::Client;

type Result<T> = error_stack::Result<T, ProviderError>;

#[automock]
#[async_trait]
pub trait SuiClient {
    async fn transaction_blocks(
        &self,
        digests: HashSet<TransactionDigest>,
    ) -> Result<Vec<Option<SuiTransactionBlockResponse>>>;
}

#[async_trait]
impl<P> SuiClient for Client<P>
where
    P: JsonRpcClient + Send + Sync + 'static,
{
    async fn transaction_blocks(
        &self,
        digests: HashSet<TransactionDigest>,
    ) -> Result<Vec<Option<SuiTransactionBlockResponse>>> {
        self.request(
            "sui_multiGetTransactionBlocks",
            (
                digests
                    .iter()
                    .map(TransactionDigest::base58_encode)
                    .collect::<Vec<_>>(),
                SuiTransactionBlockResponseOptions::new().with_events(),
            ),
        )
        .await
        .map(|vec: Vec<SuiTransactionBlockResponse>| {
            vec.into_iter()
                // None checkpoint means the transaction is not finalized
                .map(|block| block.checkpoint.map(|_| block))
                .collect()
        })
    }
}

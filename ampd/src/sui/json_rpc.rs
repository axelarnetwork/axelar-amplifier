use std::collections::{HashMap, HashSet};

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
    async fn finalized_transaction_block(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<SuiTransactionBlockResponse>>;
    async fn finalized_transaction_blocks(
        &self,
        digests: HashSet<TransactionDigest>,
    ) -> Result<HashMap<TransactionDigest, SuiTransactionBlockResponse>>;
}

#[async_trait]
impl<P> SuiClient for Client<P>
where
    P: JsonRpcClient + Send + Sync + 'static,
{
    async fn finalized_transaction_block(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<SuiTransactionBlockResponse>> {
        self.request(
            "sui_getTransactionBlock",
            (
                digest.base58_encode(),
                SuiTransactionBlockResponseOptions::new().with_events(),
            ),
        )
        .await
        // Checkpoint number exits when this transaction was included and finalized.
        .map(|block: SuiTransactionBlockResponse| block.checkpoint.map(|_| block))
    }

    async fn finalized_transaction_blocks(
        &self,
        digests: HashSet<TransactionDigest>,
    ) -> Result<HashMap<TransactionDigest, SuiTransactionBlockResponse>> {
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
                // Checkpoint number exits when this transaction was included and finalized.
                .filter(|block| block.checkpoint.is_some())
                .map(|block| (block.digest, block))
                .collect()
        })
    }
}

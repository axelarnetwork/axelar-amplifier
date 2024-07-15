use std::{num::NonZeroUsize, sync::Arc};

use lru::LruCache;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client_api::client_error::Result as ClientResult;
use solana_sdk::signature::Signature;
use solana_transaction_status::{EncodedConfirmedTransactionWithStatusMeta, UiTransactionEncoding};
use tokio::sync::RwLock;

type SyncTxLruCache = RwLock<LruCache<Signature, Arc<EncodedConfirmedTransactionWithStatusMeta>>>;

pub struct RpcCacheWrapper {
    rpc_client: RpcClient,
    tx_cache: SyncTxLruCache,
}

impl RpcCacheWrapper {
    pub fn new(rpc_client: RpcClient, max_cache_entries: NonZeroUsize) -> Self {
        Self {
            rpc_client,
            tx_cache: RwLock::new(LruCache::new(max_cache_entries)),
        }
    }

    pub async fn get_transaction(
        &self,
        signature: &Signature,
        encoding: UiTransactionEncoding,
    ) -> ClientResult<Arc<EncodedConfirmedTransactionWithStatusMeta>> {
        let mut tx_cache = self.tx_cache.write().await;

        if let Some(cached_tx) = tx_cache.get(signature) {
            return Ok(cached_tx.to_owned());
        }

        let tx = Arc::new(self.rpc_client.get_transaction(signature, encoding).await?);

        tx_cache.put(*signature, tx.clone());

        Ok(tx)
    }

    #[cfg(test)]
    pub async fn entries(&self) -> usize {
        self.tx_cache.read().await.len()
    }
}

#[cfg(test)]
mod tests {

    use std::num::NonZeroUsize;

    use crate::solana::test_utils::rpc_client_with_recorder;

    use super::*;
    use solana_client::rpc_request::RpcRequest;
    use tokio::test as async_test;

    #[async_test]
    async fn rpc_cache_wrapper_works() {
        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();
        let wrapped_rpc_client = RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(2).unwrap());

        let tx_signature = Signature::new_unique();

        wrapped_rpc_client
            .get_transaction(&tx_signature, UiTransactionEncoding::Json)
            .await
            .unwrap();
        wrapped_rpc_client
            .get_transaction(&tx_signature, UiTransactionEncoding::Json)
            .await
            .unwrap();

        assert_eq!(
            Some(&1),
            rpc_recorder.read().await.get(&RpcRequest::GetTransaction)
        );
    }

    #[async_test]
    async fn rpc_cache_wrapper_discards_old_entries() {
        let (rpc_client, _) = rpc_client_with_recorder();
        let wrapped_rpc_client = RpcCacheWrapper::new(rpc_client, NonZeroUsize::new(2).unwrap());

        for _ in 0..10 {
            let tx_signature = Signature::new_unique();

            wrapped_rpc_client
                .get_transaction(&tx_signature, UiTransactionEncoding::Json)
                .await
                .unwrap();
        }

        assert_eq!(2, wrapped_rpc_client.entries().await);
    }
}

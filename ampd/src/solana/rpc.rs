use std::{collections::HashMap, sync::Arc};

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client_api::client_error::Result as ClientResult;
use solana_sdk::signature::Signature;
use solana_transaction_status::{EncodedConfirmedTransactionWithStatusMeta, UiTransactionEncoding};
use tokio::sync::RwLock;
pub struct RpcCacheWrapper {
    rpc_client: RpcClient,
    tx_cache: RwLock<HashMap<Signature, Arc<EncodedConfirmedTransactionWithStatusMeta>>>,
}

impl RpcCacheWrapper {
    pub fn new(rpc_client: RpcClient) -> Self {
        Self {
            rpc_client,
            tx_cache: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get_transaction(
        &self,
        signature: &Signature,
        encoding: UiTransactionEncoding,
    ) -> ClientResult<Arc<EncodedConfirmedTransactionWithStatusMeta>> {
        if let Some(cached_tx) = self.tx_cache.read().await.get(signature) {
            return Ok(cached_tx.to_owned());
        }

        let tx = Arc::new(self.rpc_client.get_transaction(signature, encoding).await?);

        self.tx_cache
            .write()
            .await
            .insert(signature.clone(), tx.clone());

        Ok(tx)
    }
}

#[cfg(test)]
mod tests {

    use crate::solana::test_utils::rpc_client_with_recorder;

    use super::*;
    use solana_client::rpc_request::RpcRequest;
    use tokio::test as async_test;

    #[async_test]
    async fn rpc_cache_wrapper_works() {
        let (rpc_client, rpc_recorder) = rpc_client_with_recorder();
        let wrapped_rpc_client = RpcCacheWrapper::new(rpc_client);

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
}

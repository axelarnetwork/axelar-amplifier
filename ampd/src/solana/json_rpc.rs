use async_trait::async_trait;
use ethers::providers::{JsonRpcClient, ProviderError};
use mockall::automock;
use solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta;

use crate::json_rpc::Client;

type Result<T> = error_stack::Result<T, ProviderError>;

#[automock]
#[async_trait]
pub trait SolanaClient {
    async fn get_transaction(
        &self,
        signature_str: String,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta>;
}

#[async_trait]
impl<P> SolanaClient for Client<P>
where
    P: JsonRpcClient + Send + Sync + 'static,
{
    async fn get_transaction(
        &self,
        signature_str: String,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta> {
        self.request("getTransaction", [signature_str, String::from("json")])
            .await
    }
}

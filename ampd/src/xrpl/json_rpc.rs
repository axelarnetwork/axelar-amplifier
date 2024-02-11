use async_trait::async_trait;
use mockall::automock;
use crate::handlers::xrpl_verify_msg::TransactionId;
use xrpl_http_client::{TxRequest, TxResponse, Client, error};

type Result<T> = error_stack::Result<T, error::Error>;

#[automock]
#[async_trait]
pub trait XRPLClient {
    async fn fetch_tx(
        &self,
        tx_id: &TransactionId,
    ) -> Result<TxResponse>;
}

#[async_trait]
impl XRPLClient for Client
{
    async fn fetch_tx(
        &self,
        tx_id: &TransactionId,
    ) -> Result<TxResponse> {
        let req = TxRequest::new(tx_id.as_str());

        Ok(self.call(req).await?)
    }
}
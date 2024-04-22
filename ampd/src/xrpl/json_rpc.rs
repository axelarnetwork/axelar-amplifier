use async_trait::async_trait;
use mockall::automock;
use crate::xrpl::types::TransactionId;
use xrpl_http_client::{TxRequest, TxResponse, Client, error};

type Result<T> = error_stack::Result<T, error::Error>;

#[automock]
#[async_trait]
pub trait XRPLClient {
    async fn fetch_tx(
        &self,
        tx_id: &TransactionId,
    ) -> Result<Option<TxResponse>>;
}

#[async_trait]
impl XRPLClient for Client {
    async fn fetch_tx(&self, tx_id: &TransactionId) -> Result<Option<TxResponse>> {
        let req = TxRequest::new(tx_id.as_str());
        self.call(req).await.map(Some).or_else(|err| match err {
            error::Error::Api(reason) if reason == "txnNotFound" => Ok(None),
            _ => Err(err.into()),
        })
    }
}

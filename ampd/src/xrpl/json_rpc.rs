use async_trait::async_trait;
use cosmwasm_std::HexBinary;
use mockall::automock;
use xrpl_http_client::{error, Client, TxRequest, TxResponse};

type Result<T> = error_stack::Result<T, error::Error>;

#[automock]
#[async_trait]
pub trait XRPLClient {
    async fn tx(&self, tx_id: [u8; 32]) -> Result<Option<TxResponse>>;
}

#[async_trait]
impl XRPLClient for Client {
    async fn tx(&self, tx_id: [u8; 32]) -> Result<Option<TxResponse>> {
        let req = TxRequest::new(HexBinary::from(tx_id).to_string().as_str());
        self.call(req).await.map(Some).or_else(|err| match err {
            error::Error::Api(reason) if reason == "txnNotFound" => Ok(None),
            _ => Err(err.into()),
        })
    }
}

use async_trait::async_trait;
use cosmwasm_std::HexBinary;
use mockall::automock;
use router_api::ChainName;
use xrpl_http_client::{error, Client as XrplHttpClient, TxRequest, TxResponse};

use crate::monitoring;
use crate::monitoring::metrics::Msg;

type Result<T> = error_stack::Result<T, error::Error>;

pub struct Client {
    client: XrplHttpClient,
    monitoring_client: monitoring::Client,
    chain_name: ChainName,
}

impl Client {
    pub fn new(
        client: XrplHttpClient,
        monitoring_client: monitoring::Client,
        chain_name: ChainName,
    ) -> Self {
        Client {
            client,
            monitoring_client,
            chain_name,
        }
    }
}

#[automock]
#[async_trait]
pub trait XRPLClient {
    async fn tx(&self, tx_id: [u8; 32]) -> Result<Option<TxResponse>>;
}

#[async_trait]
impl XRPLClient for Client {
    async fn tx(&self, tx_id: [u8; 32]) -> Result<Option<TxResponse>> {
        let req = TxRequest::new(HexBinary::from(tx_id).to_string().as_str());
        let res = self.client.call(req).await;

        self.monitoring_client
            .metrics()
            .record_metric(Msg::RpcCall {
                chain_name: self.chain_name.clone(),
                success: res.is_ok(),
            });

        res.map(Some).or_else(|err| match err {
            error::Error::Api(reason) if reason == "txnNotFound" => Ok(None),
            _ => Err(err.into()),
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use router_api::ChainName;
    use xrpl_http_client::Client as XrplHttpClient;

    use super::{Client, XRPLClient};
    use crate::monitoring::metrics::Msg;
    use crate::monitoring::test_utils;

    #[tokio::test]
    async fn should_record_rpc_error_metrics_when_rpc_fails() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let xrpl_client = XrplHttpClient::builder()
            .base_url("http://invalid-url-that-will-fail")
            .http_client(
                reqwest::ClientBuilder::new()
                    .timeout(std::time::Duration::from_millis(1))
                    .build()
                    .unwrap(),
            )
            .build();

        let client = Client::new(
            xrpl_client,
            monitoring_client,
            ChainName::from_str("xrpl").unwrap(),
        );

        let tx_id = [0u8; 32];
        let result = client.tx(tx_id).await;
        assert!(result.is_err());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcCall {
                chain_name: ChainName::from_str("xrpl").unwrap(),
                success: false,
            }
        );

        assert!(receiver.try_recv().is_err());
    }
}

use std::fmt;
use std::fmt::Debug;

use error_stack::Report;
use ethers_providers::{Http, JsonRpcClient, ProviderError};
use router_api::ChainName;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::monitoring;
use crate::monitoring::metrics::Msg;
use crate::types::debug::REDACTED_VALUE;
use crate::url::Url;

type Result<T> = error_stack::Result<T, ProviderError>;

pub struct Client<P>
where
    P: JsonRpcClient,
{
    provider: P,
    monitoring_client: monitoring::Client,
    chain_name: ChainName,
}

impl<P> Client<P>
where
    P: JsonRpcClient,
{
    pub fn new(provider: P, monitoring_client: monitoring::Client, chain_name: ChainName) -> Self {
        Client {
            provider,
            monitoring_client,
            chain_name,
        }
    }

    pub async fn request<T, R>(&self, method: &str, params: T) -> Result<R>
    where
        T: Debug + Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        let res = self
            .provider
            .request(method, params)
            .await
            .map_err(Into::into)
            .map_err(Report::from);

        self.monitoring_client
            .metrics()
            .record_metric(Msg::RpcCall {
                chain_name: self.chain_name.clone(),
                success: res.is_ok(),
            });

        res
    }
}

impl Client<Http> {
    pub fn new_http(
        url: Url,
        client: reqwest::Client,
        monitoring_client: monitoring::Client,
        chain_name: ChainName,
    ) -> Self {
        Client::new(
            Http::new_with_client(url, client),
            monitoring_client,
            chain_name,
        )
    }
}

impl Debug for Client<Http> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("provider", &REDACTED_VALUE)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use std::fmt::Debug;
    use std::str::FromStr;

    use async_trait::async_trait;
    use ethers_providers::{JsonRpcClient, ProviderError};
    use router_api::ChainName;
    use serde::de::DeserializeOwned;
    use serde::Serialize;

    use super::Client;
    use crate::monitoring::metrics::Msg;
    use crate::monitoring::test_utils;

    #[derive(Debug, Clone)]
    pub struct FailingJsonRpcClient;

    #[async_trait]
    impl JsonRpcClient for FailingJsonRpcClient {
        type Error = ProviderError;

        async fn request<T, R>(&self, _method: &str, _params: T) -> Result<R, Self::Error>
        where
            T: Debug + Serialize + Send + Sync,
            R: DeserializeOwned + Send,
        {
            Err(ProviderError::UnsupportedNodeClient)
        }
    }

    #[derive(Debug, Clone)]
    pub struct ValidJsonRpcClient;

    #[async_trait]
    impl JsonRpcClient for ValidJsonRpcClient {
        type Error = ProviderError;

        async fn request<T, R>(&self, _: &str, _: T) -> Result<R, Self::Error>
        where
            T: Debug + Serialize + Send + Sync,
            R: DeserializeOwned + Send,
        {
            serde_json::from_value(serde_json::json!("0x1")).map_err(ProviderError::SerdeJson)
        }
    }

    #[tokio::test]
    async fn should_record_rpc_failure_metrics_successfully() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let client = Client::new(
            FailingJsonRpcClient,
            monitoring_client,
            ChainName::from_str("ethereum").unwrap(),
        );

        let result: Result<String, _> = client.request("parameter", serde_json::json!([])).await;
        assert!(result.is_err());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcCall {
                chain_name: ChainName::from_str("ethereum").unwrap(),
                success: false,
            }
        );
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn should_record_rpc_success_metrics_when_mock_succeeds() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let client = Client::new(
            ValidJsonRpcClient,
            monitoring_client,
            ChainName::from_str("ethereum").unwrap(),
        );

        let result: Result<String, _> = client.request("parameter", serde_json::json!([])).await;

        assert!(result.is_ok());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcCall {
                chain_name: ChainName::from_str("ethereum").unwrap(),
                success: true,
            }
        );

        assert!(receiver.try_recv().is_err());
    }
}

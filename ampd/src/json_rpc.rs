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
        self.provider
            .request(method, params)
            .await
            .map_err(Into::into)
            .map_err(Report::from)
            .inspect_err(|_| {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::RpcError {
                        chain_name: self.chain_name.clone(),
                    });
            })
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
    use std::str::FromStr;

    use router_api::ChainName;

    use super::Client;
    use crate::monitoring::metrics::Msg;
    use crate::monitoring::test_utils;
    use crate::url::Url;

    #[tokio::test]
    async fn should_record_rpc_error_metrics_when_rpc_fails() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let client = Client::new_http(
            Url::new_sensitive("http://localhost:9999").unwrap(),
            reqwest::ClientBuilder::new()
                .timeout(std::time::Duration::from_millis(1))
                .build()
                .unwrap(),
            monitoring_client,
            ChainName::from_str("ethereum").unwrap(),
        );

        let result = client
            .request::<[serde_json::Value; 0], serde_json::Value>("non_existing_method", [])
            .await;
        assert!(result.is_err());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcError {
                chain_name: ChainName::from_str("ethereum").unwrap(),
            }
        );

        assert!(receiver.try_recv().is_err());
    }
}
use std::fmt;
use std::fmt::Debug;

use error_stack::Report;
use ethers_providers::{Http, JsonRpcClient, ProviderError};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::types::debug::REDACTED_VALUE;
use crate::url::Url;

type Result<T> = error_stack::Result<T, ProviderError>;

pub struct Client<P>
where
    P: JsonRpcClient,
{
    provider: P,
}

impl<P> Client<P>
where
    P: JsonRpcClient,
{
    pub fn new(provider: P) -> Self {
        Client { provider }
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
    }
}

impl Client<Http> {
    pub fn new_http(url: Url, client: reqwest::Client) -> Self {
        Client::new(Http::new_with_client(url, client))
    }
}

impl Debug for Client<Http> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("provider", &REDACTED_VALUE)
            .finish()
    }
}

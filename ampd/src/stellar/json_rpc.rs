use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use error_stack::Result;
use mockall::automock;

use crate::stellar::rpc_client::{Client, Error, TxResponse};

#[automock]
#[async_trait]
pub trait StellarClient {
    async fn transaction_response(&self, tx_hash: String) -> Result<Option<TxResponse>, Error>;
    async fn transaction_responses(
        &self,
        tx_hashes: HashSet<String>,
    ) -> Result<HashMap<String, TxResponse>, Error>;
}

#[async_trait]
impl StellarClient for Client {
    async fn transaction_response(&self, tx_hash: String) -> Result<Option<TxResponse>, Error> {
        self.transaction_response(tx_hash).await
    }

    async fn transaction_responses(
        &self,
        tx_hashes: HashSet<String>,
    ) -> Result<HashMap<String, TxResponse>, Error> {
        self.transaction_responses(tx_hashes).await
    }
}

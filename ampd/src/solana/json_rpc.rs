use async_trait::async_trait;
use ethers::providers::{JsonRpcClient, ProviderError};
use mockall::automock;
use serde::{Deserialize, Serialize};
use solana_account_decoder::UiAccountEncoding;
use solana_sdk::commitment_config::{CommitmentConfig, CommitmentLevel};
// use solana_sdk::transaction::Transaction;

use crate::json_rpc::Client;

type Result<T> = error_stack::Result<T, ProviderError>;

// TODO: This should come from solana-sdk crate
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub message: SolMessage,
    pub signatures: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolMessage {
    pub instructions: Vec<SolInstruction>,
    pub account_keys: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiTransactionStatusMeta {
    pub log_messages: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SolInstruction {
    pub data: String,
}

// TODO: This should come from the solana-transaction-status crate
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct EncodedConfirmedTransactionWithStatusMeta {
    pub transaction: Transaction,
    pub meta: UiTransactionStatusMeta,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountInfo {
    pub value: AccountInfoValue,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountInfoValue {
    pub data: Vec<String>,
}

#[automock]
#[async_trait]
pub trait SolanaClient {
    async fn get_transaction(
        &self,
        signature_str: &str,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta>;

    async fn get_account_info(&self, pub_key: &str) -> Result<AccountInfo>;
}

#[async_trait]
impl<P> SolanaClient for Client<P>
where
    P: JsonRpcClient + Send + Sync + 'static,
{
    // Gets an account with default commitment set to finalized. See (https://solana.com/docs/rpc/http/gettransaction)
    async fn get_transaction(
        &self,
        signature_str: &str,
    ) -> Result<EncodedConfirmedTransactionWithStatusMeta> {
        self.request("getTransaction", [signature_str, "json"])
            .await
    }
    // Gets an account with default commitment set to finalized. See (https://solana.com/docs/rpc/http/getaccountinfo)
    async fn get_account_info(&self, pub_key: &str) -> Result<AccountInfo> {
        let config = solana_client::rpc_config::RpcAccountInfoConfig {
            commitment: Some(CommitmentConfig {
                commitment: CommitmentLevel::Finalized,
            }),
            encoding: Some(UiAccountEncoding::Base64),
            data_slice: None,
            min_context_slot: None,
        };
        self.request("getAccountInfo", (pub_key, config)).await
    }
}

// Exploratory tests for checking integration with Solana. This could be automated in some way
// in the future. See https://solana.com/developers/guides/getstarted/setup-local-development .

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use super::*;
    use crate::url::Url;
    use tokio::test as async_test;

    const RPC_URL: &str = "http://127.0.0.1:8899"; // default.

    #[async_test]
    async fn test_get_transaction_works() {
        // pubkey: EHgEeD1Z3pc29s3JKhfVv9AGk7HkQFZKkcHbkypdN1h6
        let url = Url::from_str(RPC_URL).unwrap();
        let client = Client::new_http(&url).unwrap();
        let tx = client.get_transaction("<your transaction signature>").await.unwrap();
        println!("tx - {}", tx.transaction.signatures[0]);
    }

    #[async_test]
    async fn test_get_account_works() {
        let url = Url::from_str(RPC_URL).unwrap();
        let client = Client::new_http(&url).unwrap();
        let acc = client
            .get_account_info("<your account pub_key>")
            .await
            .unwrap();
        println!("acc - {:?}", acc.value.data);
    }
}

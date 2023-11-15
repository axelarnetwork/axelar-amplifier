use async_trait::async_trait;
use futures::future::join_all;
use mockall::automock;
use multiversx_sdk::blockchain::CommunicationProxy;
use multiversx_sdk::data::transaction::TransactionOnNetwork;
use std::collections::{HashMap, HashSet};
use crate::handlers::errors::Error;

type Result<T> = error_stack::Result<T, Error>;

const STATUS_SUCCESS: &str = "success";

#[automock]
#[async_trait]
pub trait MvxProxy {
    async fn transactions_info_with_results(
        &self,
        tx_hashes: HashSet<String>,
    ) -> Result<HashMap<String, TransactionOnNetwork>>;
}

#[async_trait]
impl MvxProxy for CommunicationProxy {
    async fn transactions_info_with_results(
        &self,
        tx_hashes: HashSet<String>,
    ) -> Result<HashMap<String, TransactionOnNetwork>> {
        Ok(join_all(
            tx_hashes
                .iter()
                .map(|tx_hash| self.get_transaction_info_with_results(tx_hash.as_str())),
        )
        .await
        .into_iter()
        .filter_map(|tx| {
            if !tx.is_ok() {
                return None;
            }

            let tx = tx.unwrap();

            if tx.hash.is_none() || tx.logs.is_none() || tx.status != STATUS_SUCCESS.to_string() {
                return None;
            }

            Some((tx.hash.clone().unwrap(), tx))
        })
        .collect())
    }
}

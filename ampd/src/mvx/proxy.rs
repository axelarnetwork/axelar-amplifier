use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use futures::future::join_all;
use hex::ToHex;
use mockall::automock;
use multiversx_sdk::blockchain::CommunicationProxy;
use multiversx_sdk::data::transaction::TransactionOnNetwork;

use crate::handlers::errors::Error;
use crate::types::Hash;

type Result<T> = error_stack::Result<T, Error>;

const STATUS_SUCCESS: &str = "success";

#[automock]
#[async_trait]
pub trait MvxProxy {
    async fn transactions_info_with_results(
        &self,
        tx_hashes: HashSet<Hash>,
    ) -> Result<HashMap<Hash, TransactionOnNetwork>>;

    async fn transaction_info_with_results(
        &self,
        tx_hash: &Hash,
    ) -> Result<Option<TransactionOnNetwork>>;

    fn is_valid_transaction(tx: &TransactionOnNetwork) -> bool;
}

#[async_trait]
impl MvxProxy for CommunicationProxy {
    async fn transactions_info_with_results(
        &self,
        tx_hashes: HashSet<Hash>,
    ) -> Result<HashMap<Hash, TransactionOnNetwork>> {
        let tx_hashes: Vec<String> = tx_hashes
            .iter()
            .map(|tx_hash| tx_hash.encode_hex::<String>())
            .collect();

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

                if !Self::is_valid_transaction(&tx) {
                    return None;
                }

                Some((tx.hash.clone().unwrap().parse().unwrap(), tx))
            })
            .collect())
    }

    async fn transaction_info_with_results(
        &self,
        tx_hash: &Hash,
    ) -> Result<Option<TransactionOnNetwork>> {
        let tx = self
            .get_transaction_info_with_results(tx_hash.encode_hex::<String>().as_str())
            .await;

        if !tx.is_ok() {
            return Ok(None);
        }

        let tx = tx.unwrap();

        if !Self::is_valid_transaction(&tx) {
            return Ok(None);
        }

        Ok(Some(tx))
    }

    fn is_valid_transaction(tx: &TransactionOnNetwork) -> bool {
        if tx.hash.is_none() || tx.logs.is_none() || tx.status != STATUS_SUCCESS.to_string() {
            return false;
        }

        true
    }
}

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use futures::future::join_all;
use hex::ToHex;
use mockall::automock;
use multiversx_sdk::blockchain::CommunicationProxy;
use multiversx_sdk::data::transaction::TransactionOnNetwork;

use crate::types::Hash;

const STATUS_SUCCESS: &str = "success";

#[automock]
#[async_trait]
pub trait MvxProxy {
    async fn transactions_info_with_results(
        &self,
        tx_hashes: HashSet<Hash>,
    ) -> HashMap<Hash, TransactionOnNetwork>;

    async fn transaction_info_with_results(&self, tx_hash: &Hash) -> Option<TransactionOnNetwork>;

    fn is_valid_transaction(tx: &TransactionOnNetwork) -> bool;
}

#[async_trait]
impl MvxProxy for CommunicationProxy {
    async fn transactions_info_with_results(
        &self,
        tx_hashes: HashSet<Hash>,
    ) -> HashMap<Hash, TransactionOnNetwork> {
        let tx_hashes = Vec::from_iter(tx_hashes);

        let txs = join_all(
            tx_hashes
                .iter()
                .map(|tx_hash| self.transaction_info_with_results(tx_hash)),
        )
        .await;

        tx_hashes
            .into_iter()
            .zip(txs)
            .filter_map(|(hash, tx)| {
                tx.as_ref()?;

                Some((hash, tx.unwrap()))
            })
            .collect()
    }

    async fn transaction_info_with_results(&self, tx_hash: &Hash) -> Option<TransactionOnNetwork> {
        self.get_transaction_info_with_results(tx_hash.encode_hex::<String>().as_str())
            .await
            .ok()
            .filter(Self::is_valid_transaction)
    }

    fn is_valid_transaction(tx: &TransactionOnNetwork) -> bool {
        tx.hash.is_some() && tx.logs.is_some() && tx.status == *STATUS_SUCCESS
    }
}

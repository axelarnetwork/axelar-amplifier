use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use futures::future::join_all;
use hex::ToHex;
use mockall::automock;
use multiversx_sdk::data::transaction::TransactionOnNetwork;
use multiversx_sdk::gateway::GatewayProxy;

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
impl MvxProxy for GatewayProxy {
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

    /// First check if a transaction has hash & logs which are required in order to parse events.
    /// Then make sure transactions are included on the blockchain (STATUS_SUCCESS) and
    /// are final (included in a hyperblock by checking notarized_at_source_in_meta_nonce).
    /// For more information regarding finality see:
    /// https://docs.multiversx.com/integrators/egld-integration-guide/#finality-of-the-transactions--number-of-confirmations
    fn is_valid_transaction(tx: &TransactionOnNetwork) -> bool {
        tx.hash.is_some()
            && tx.logs.is_some()
            && tx.status == *STATUS_SUCCESS
            && tx.notarized_at_source_in_meta_nonce.is_some()
    }
}

#[cfg(test)]
mod tests {
    use multiversx_sdk::data::address::Address;
    use multiversx_sdk::data::transaction::{ApiLogs, TransactionOnNetwork};
    use multiversx_sdk::gateway::GatewayProxy;

    use super::MvxProxy;

    #[test]
    fn should_not_be_valid_transaction_no_hash() {
        let tx = TransactionOnNetwork {
            hash: None,
            ..TransactionOnNetwork::default()
        };

        assert!(!GatewayProxy::is_valid_transaction(&tx));
    }

    #[test]
    fn should_not_be_valid_transaction_no_logs() {
        let tx = TransactionOnNetwork {
            hash: Some("txHash".into()),
            logs: None,
            ..TransactionOnNetwork::default()
        };

        assert!(!GatewayProxy::is_valid_transaction(&tx));
    }

    #[test]
    fn should_not_be_valid_transaction_invalid_status() {
        let tx = TransactionOnNetwork {
            hash: Some("txHash".into()),
            logs: Some(ApiLogs {
                address: Address::from_bech32_string(
                    "erd1qqqqqqqqqqqqqpgqhe8t5jewej70zupmh44jurgn29psua5l2jps3ntjj3",
                )
                .unwrap(),
                events: vec![],
            }),
            status: "pending".into(),
            ..TransactionOnNetwork::default()
        };

        assert!(!GatewayProxy::is_valid_transaction(&tx));
    }

    #[test]
    fn should_not_be_valid_transaction_invalid_notarized_at_source_in_meta_nonce() {
        let tx = TransactionOnNetwork {
            hash: Some("txHash".into()),
            logs: Some(ApiLogs {
                address: Address::from_bech32_string(
                    "erd1qqqqqqqqqqqqqpgqhe8t5jewej70zupmh44jurgn29psua5l2jps3ntjj3",
                )
                .unwrap(),
                events: vec![],
            }),
            status: "success".into(),
            notarized_at_source_in_meta_nonce: None,
            ..TransactionOnNetwork::default()
        };

        assert!(!GatewayProxy::is_valid_transaction(&tx));
    }

    #[test]
    fn should_be_valid_transaction() {
        let tx = TransactionOnNetwork {
            hash: Some("txHash".into()),
            logs: Some(ApiLogs {
                address: Address::from_bech32_string(
                    "erd1qqqqqqqqqqqqqpgqhe8t5jewej70zupmh44jurgn29psua5l2jps3ntjj3",
                )
                .unwrap(),
                events: vec![],
            }),
            status: "success".into(),
            notarized_at_source_in_meta_nonce: Some(1),
            ..TransactionOnNetwork::default()
        };

        assert!(GatewayProxy::is_valid_transaction(&tx));
    }
}

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use futures::future::join_all;
use hex::ToHex;
use mockall::automock;
use multiversx_sdk::data::transaction::TransactionOnNetwork;
use multiversx_sdk::gateway::GatewayProxy;
use router_api::ChainName;

use crate::monitoring;
use crate::monitoring::metrics::Msg;
use crate::types::Hash;

const STATUS_SUCCESS: &str = "success";

pub struct Client {
    proxy: GatewayProxy,
    monitoring_client: monitoring::Client,
    chain_name: ChainName,
}

impl Client {
    pub fn new(
        proxy: GatewayProxy,
        monitoring_client: monitoring::Client,
        chain_name: ChainName,
    ) -> Self {
        Client {
            proxy,
            monitoring_client,
            chain_name,
        }
    }
}

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
impl MvxProxy for Client {
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

                Some((hash, tx.expect("tx should be valid")))
            })
            .collect()
    }

    async fn transaction_info_with_results(&self, tx_hash: &Hash) -> Option<TransactionOnNetwork> {
        self.proxy
            .get_transaction_info_with_results(tx_hash.encode_hex::<String>().as_str())
            .await
            .inspect_err(|_| {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::RpcError {
                        chain_name: self.chain_name.clone(),
                    });
            })
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
    use std::str::FromStr;

    use multiversx_sdk::data::address::Address;
    use multiversx_sdk::data::transaction::{ApiLogs, TransactionOnNetwork};
    use multiversx_sdk::gateway::GatewayProxy;
    use router_api::ChainName;

    use super::{Client, MvxProxy};
    use crate::monitoring::metrics::Msg;
    use crate::monitoring::test_utils;
    use crate::types::Hash;

    #[test]
    fn should_not_be_valid_transaction_no_hash() {
        let tx = TransactionOnNetwork {
            hash: None,
            ..TransactionOnNetwork::default()
        };

        assert!(!Client::is_valid_transaction(&tx));
    }

    #[test]
    fn should_not_be_valid_transaction_no_logs() {
        let tx = TransactionOnNetwork {
            hash: Some("txHash".into()),
            logs: None,
            ..TransactionOnNetwork::default()
        };

        assert!(!Client::is_valid_transaction(&tx));
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

        assert!(!Client::is_valid_transaction(&tx));
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

        assert!(!Client::is_valid_transaction(&tx));
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

        assert!(Client::is_valid_transaction(&tx));
    }

    #[tokio::test]
    async fn should_record_rpc_error_metrics_when_rpc_fails() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let gateway_proxy = GatewayProxy::new("http://invalid-url-that-will-fail".into());

        let client = Client::new(
            gateway_proxy,
            monitoring_client,
            ChainName::from_str("multiversx").unwrap(),
        );

        let tx_hash = Hash::from([0u8; 32]);
        let result = client.transaction_info_with_results(&tx_hash).await;
        assert!(result.is_none());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcError {
                chain_name: ChainName::from_str("multiversx").unwrap(),
            }
        );

        assert!(receiver.try_recv().is_err());
    }
}
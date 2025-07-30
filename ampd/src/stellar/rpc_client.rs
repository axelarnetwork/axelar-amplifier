use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use error_stack::{report, ResultExt};
use futures::future::join_all;
use router_api::ChainName;
use stellar_rpc_client::GetTransactionResponse;
use stellar_xdr::curr::{ContractEvent, Hash, TransactionMeta, VecM};
use thiserror::Error;
use tracing::warn;

use crate::monitoring;
use crate::monitoring::metrics::Msg;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create client")]
    Client,
    #[error("invalid tx hash")]
    TxHash,
}

/// TxResponse parses XDR encoded TransactionMeta to ContractEvent type, and only contains necessary fields for verification
#[derive(Debug)]
pub struct TxResponse {
    pub transaction_hash: String,
    pub successful: bool,
    pub contract_events: VecM<ContractEvent>,
}

const STATUS_SUCCESS: &str = "SUCCESS";

impl From<(Hash, GetTransactionResponse)> for TxResponse {
    fn from((transaction_hash, response): (Hash, GetTransactionResponse)) -> Self {
        let contract_events = response
            .result_meta
            .and_then(|meta| match meta {
                TransactionMeta::V3(data) => data.soroban_meta.map(|meta| meta.events),
                _ => None,
            })
            .unwrap_or_default();

        Self {
            transaction_hash: transaction_hash.to_string(),
            successful: response.status == STATUS_SUCCESS,
            contract_events,
        }
    }
}

impl TxResponse {
    pub fn has_failed(&self) -> bool {
        !self.successful
    }

    pub fn event(&self, index: u64) -> Option<&ContractEvent> {
        let log_index = usize::try_from(index).ok()?;
        self.contract_events.get(log_index)
    }

    pub fn tx_hash(&self) -> String {
        self.transaction_hash.clone()
    }
}

#[cfg_attr(test, faux::create)]
#[derive(Debug)]
pub struct Client {
    client: stellar_rpc_client::Client,
    monitoring_client: monitoring::Client,
    chain_name: ChainName,
}

#[cfg_attr(test, faux::methods)]
impl Client {
    pub fn new(
        url: String,
        monitoring_client: monitoring::Client,
        chain_name: ChainName,
    ) -> error_stack::Result<Self, Error> {
        let client = stellar_rpc_client::Client::new(url.as_str())
            .map_err(|err_str| report!(Error::Client).attach_printable(err_str))?;

        Ok(Self {
            client,
            monitoring_client,
            chain_name,
        })
    }

    pub async fn transaction_responses(
        &self,
        tx_hashes: HashSet<String>,
    ) -> error_stack::Result<HashMap<String, TxResponse>, Error> {
        let tx_hashes: Vec<_> = tx_hashes
            .into_iter()
            .map(|tx_hash| Hash::from_str(tx_hash.as_str()).change_context(Error::TxHash))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let responses = join_all(
            tx_hashes
                .iter()
                .map(|tx_hash| self.client.get_transaction(tx_hash)),
        )
        .await;

        Ok(responses
            .into_iter()
            .zip(tx_hashes)
            .filter_map(|(response, hash)| match response {
                Ok(resp) => {
                    let tx_response = TxResponse::from((hash, resp));
                    Some((tx_response.tx_hash(), tx_response))
                }
                Err(err) => {
                    self.monitoring_client
                        .metrics()
                        .record_metric(Msg::RpcError {
                            chain_name: self.chain_name.clone(),
                        });
                    warn!(error = ?err, tx_hash = ?hash, "failed to get transaction response");
                    None
                }
            })
            .collect::<HashMap<_, _>>())
    }

    pub async fn transaction_response(
        &self,
        tx_hash: String,
    ) -> error_stack::Result<Option<TxResponse>, Error> {
        let tx_hash = Hash::from_str(tx_hash.as_str()).change_context(Error::TxHash)?;

        match self.client.get_transaction(&tx_hash).await {
            Ok(response) => Ok(Some(TxResponse::from((tx_hash, response)))),
            Err(err) => {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::RpcError {
                        chain_name: self.chain_name.clone(),
                    });
                warn!(error = ?err, "failed to get transaction response");
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::monitoring::test_utils;

    #[tokio::test]
    async fn should_record_rpc_error_metrics_when_rpc_fails() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let tx_hash1 =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let client = Client::new(
            "http://invalid_link".to_string(),
            monitoring_client,
            ChainName::from_str("stellar").unwrap(),
        )
        .unwrap();

        let result = client.transaction_response(tx_hash1.clone()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcError {
                chain_name: ChainName::from_str("stellar").unwrap(),
            }
        );

        let mut tx_hashes = HashSet::new();

        let tx_hash2 =
            "0000000000000000000000000000000000000000000000000000000000000001".to_string();
        tx_hashes.insert(tx_hash1.clone());
        tx_hashes.insert(tx_hash2.clone());

        let result = client.transaction_responses(tx_hashes).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        for _ in 0..2 {
            let msg = receiver.recv().await.unwrap();
            assert_eq!(
                msg,
                Msg::RpcError {
                    chain_name: ChainName::from_str("stellar").unwrap(),
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }
}

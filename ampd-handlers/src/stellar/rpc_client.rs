use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use ampd::monitoring;
use ampd::monitoring::metrics::Msg;
use ampd::url::Url;
use async_trait::async_trait;
use axelar_wasm_std::chain::ChainName;
use error_stack::{report, ResultExt};
use futures::future::join_all;
use mockall::automock;
use stellar_rpc_client::GetTransactionResponse;
use stellar_xdr::curr::{ContractEvent, Hash, TransactionMeta};
use thiserror::Error;
use tracing::warn;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create client")]
    Client,
    #[error("invalid tx hash")]
    TxHash,
}

#[derive(Error, Debug)]
pub enum TxParseError {
    #[error("Invalid operation count for Soroban transaction: expected {expected}, got {actual}")]
    InvalidOperationCount { expected: usize, actual: usize },
    #[error("Unsupported transaction metadata version")]
    UnsupportedMetadataVersion,
}

/// TxResponse parses XDR encoded TransactionMeta to ContractEvent type, and only contains necessary fields for verification
#[derive(Debug)]
pub struct TxResponse {
    pub transaction_hash: String,
    pub successful: bool,
    pub contract_events: Vec<ContractEvent>,
}

const STATUS_SUCCESS: &str = "SUCCESS";
const EXPECTED_SOROBAN_OPERATION_COUNT: usize = 1;

impl TryFrom<(Hash, GetTransactionResponse)> for TxResponse {
    type Error = TxParseError;

    fn try_from(
        (transaction_hash, response): (Hash, GetTransactionResponse),
    ) -> Result<Self, Self::Error> {
        let transaction_hash = transaction_hash.to_string();
        if response.status != STATUS_SUCCESS {
            return Ok(Self {
                transaction_hash,
                successful: false,
                contract_events: vec![],
            });
        }

        let contract_events = match response.result_meta.as_ref() {
            Some(TransactionMeta::V4(_)) => {
                // Protocol V23: Soroban contract calls should have exactly one operation.
                // This prevents potential security issues from processing multiple operations
                // or malformed transactions that could lead to event ordering confusion.
                let contract_events = response.events.contract_events;
                match contract_events.as_slice() {
                    [events] => events.clone(),
                    _ => {
                        return Err(TxParseError::InvalidOperationCount {
                            expected: EXPECTED_SOROBAN_OPERATION_COUNT,
                            actual: contract_events.len(),
                        });
                    }
                }
            }
            Some(TransactionMeta::V3(data)) => data
                .soroban_meta
                .as_ref()
                .map(|meta| meta.events.to_vec())
                .unwrap_or_default(),
            _ => {
                return Err(TxParseError::UnsupportedMetadataVersion);
            }
        };

        Ok(Self {
            transaction_hash,
            successful: true,
            contract_events,
        })
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

#[derive(Debug)]
pub struct Client {
    client: stellar_rpc_client::Client,
    monitoring_client: monitoring::Client,
    chain_name: ChainName,
}

impl Client {
    pub fn new(
        url: Url,
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

    fn validate_tx_response(
        &self,
        result: Result<GetTransactionResponse, stellar_rpc_client::Error>,
        hash: Hash,
    ) -> Option<TxResponse> {
        let response = match result {
            Ok(response) => response,
            Err(err) => {
                warn!(error = ?err, tx_hash = ?hash, "failed to get transaction response");
                return None;
            }
        };

        TxResponse::try_from((hash.clone(), response))
            .map_err(|err| {
                warn!(error = %err, tx_hash = ?hash, "failed to parse transaction response");
                err
            })
            .ok()
    }
}

#[automock]
#[async_trait]
pub trait StellarClient {
    async fn transaction_response(
        &self,
        tx_hash: String,
    ) -> error_stack::Result<Option<TxResponse>, Error>;
    async fn transaction_responses(
        &self,
        tx_hashes: HashSet<String>,
    ) -> error_stack::Result<HashMap<String, TxResponse>, Error>;
}

#[async_trait]
impl StellarClient for Client {
    async fn transaction_response(
        &self,
        tx_hash: String,
    ) -> error_stack::Result<Option<TxResponse>, Error> {
        let tx_hash = Hash::from_str(tx_hash.as_str()).change_context(Error::TxHash)?;
        let res = self.validate_tx_response(self.client.get_transaction(&tx_hash).await, tx_hash);

        self.monitoring_client
            .metrics()
            .record_metric(Msg::RpcCall {
                chain_name: self.chain_name.clone(),
                success: res.is_some(),
            });

        Ok(res)
    }

    async fn transaction_responses(
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
            .filter_map(|(response, hash)| {
                let res = self.validate_tx_response(response, hash);
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::RpcCall {
                        chain_name: self.chain_name.clone(),
                        success: res.is_some(),
                    });

                res.map(|tx_response| (tx_response.tx_hash(), tx_response))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use ampd::monitoring::test_utils;
    use stellar_rpc_client::{GetTransactionEvents, GetTransactionResponse};
    use stellar_xdr::curr::{
        ContractEvent, ContractEventBody, ContractEventType, ContractEventV0, ExtensionPoint,
        ScVal, SorobanTransactionMeta, TransactionMeta, TransactionMetaV3, TransactionMetaV4,
    };

    use super::*;

    fn create_mock_contract_event(data: u32) -> ContractEvent {
        ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: None,
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: Default::default(),
                data: ScVal::U32(data),
            }),
        }
    }

    fn create_mock_client() -> Client {
        let (monitoring_client, _) = test_utils::monitoring_client();
        Client::new(
            Url::new_non_sensitive("http://localhost").unwrap(),
            monitoring_client,
            "stellar".parse().unwrap(),
        )
        .unwrap()
    }

    fn create_mock_transaction_response_v4(
        events: Vec<Vec<ContractEvent>>,
        status: &str,
    ) -> GetTransactionResponse {
        GetTransactionResponse {
            status: status.to_string(),
            envelope: None,
            result: None,
            result_meta: Some(TransactionMeta::V4(TransactionMetaV4 {
                ..Default::default()
            })),
            events: GetTransactionEvents {
                contract_events: events,
                diagnostic_events: vec![],
                transaction_events: vec![],
            },
        }
    }

    fn create_mock_transaction_response_v3(
        events: Vec<ContractEvent>,
        status: &str,
    ) -> GetTransactionResponse {
        let soroban_meta = if events.is_empty() {
            None
        } else {
            Some(SorobanTransactionMeta {
                events: events.try_into().unwrap(),
                ..Default::default()
            })
        };

        GetTransactionResponse {
            status: status.to_string(),
            envelope: None,
            result: None,
            result_meta: Some(TransactionMeta::V3(TransactionMetaV3 {
                soroban_meta,
                ..Default::default()
            })),
            events: GetTransactionEvents {
                contract_events: vec![],
                diagnostic_events: vec![],
                transaction_events: vec![],
            },
        }
    }

    #[test]
    fn tx_response_v4_succeeds_with_valid_transaction() {
        let hash = Hash::from([1u8; 32]);
        let contract_events = vec![vec![
            create_mock_contract_event(1),
            create_mock_contract_event(2),
            create_mock_contract_event(3),
        ]];
        let response = create_mock_transaction_response_v4(contract_events, STATUS_SUCCESS);

        let tx_response = TxResponse::try_from((hash.clone(), response)).unwrap();

        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert_eq!(tx_response.contract_events.len(), 3);
        assert!(tx_response.successful);
    }

    #[test]
    fn tx_response_v4_handles_transaction_status_failed() {
        let hash = Hash::from([2u8; 32]);
        let response = create_mock_transaction_response_v4(vec![], "FAILED");

        let result = TxResponse::try_from((hash.clone(), response));

        assert!(result.is_ok());
        let tx_response = result.unwrap();
        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert!(!tx_response.successful);
        assert!(tx_response.contract_events.is_empty());
    }

    #[test]
    fn tx_response_v4_fails_with_single_empty_operation() {
        let hash = Hash::from([3u8; 32]);
        let response = create_mock_transaction_response_v4(vec![vec![]], STATUS_SUCCESS);

        let result = TxResponse::try_from((hash.clone(), response));

        assert!(result.is_ok());
        let tx_response = result.unwrap();
        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert!(tx_response.successful);
        assert!(tx_response.contract_events.is_empty());
    }

    #[test]
    fn tx_response_v4_fails_with_no_operations() {
        let hash = Hash::from([4u8; 32]);
        let response = create_mock_transaction_response_v4(vec![], STATUS_SUCCESS);

        let result = TxResponse::try_from((hash.clone(), response));

        assert!(result.is_err());
        match result.unwrap_err() {
            TxParseError::InvalidOperationCount { expected, actual } => {
                assert_eq!(expected, EXPECTED_SOROBAN_OPERATION_COUNT);
                assert_eq!(actual, 0);
            }
            _ => panic!("Expected InvalidOperationCount error"),
        }
    }

    #[test]
    fn tx_response_v4_fails_with_multiple_operations() {
        let hash = Hash::from([5u8; 32]);
        let contract_events = vec![
            vec![create_mock_contract_event(1), create_mock_contract_event(2)],
            vec![create_mock_contract_event(3)],
        ];
        let response = create_mock_transaction_response_v4(contract_events, STATUS_SUCCESS);

        let result = TxResponse::try_from((hash.clone(), response));

        assert!(result.is_err());
        match result.unwrap_err() {
            TxParseError::InvalidOperationCount { expected, actual } => {
                assert_eq!(expected, EXPECTED_SOROBAN_OPERATION_COUNT);
                assert_eq!(actual, 2);
            }
            _ => panic!("Expected InvalidOperationCount error"),
        }
    }

    #[test]
    fn tx_response_v4_fails_with_no_metadata() {
        let hash = Hash::from([6u8; 32]);
        let mut response = create_mock_transaction_response_v4(
            vec![vec![create_mock_contract_event(1)]],
            STATUS_SUCCESS,
        );
        response.result_meta = None;

        let result = TxResponse::try_from((hash.clone(), response));

        assert!(result.is_err());
        match result.unwrap_err() {
            TxParseError::UnsupportedMetadataVersion => {
                // Expected
            }
            _ => panic!("Expected UnsupportedMetadataVersion error"),
        }
    }

    #[test]
    fn tx_response_v3_succeeds_with_valid_transaction() {
        let hash = Hash::from([7u8; 32]);
        let events = vec![create_mock_contract_event(1), create_mock_contract_event(2)];
        let response = create_mock_transaction_response_v3(events, STATUS_SUCCESS);

        let tx_response = TxResponse::try_from((hash.clone(), response)).unwrap();

        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert_eq!(tx_response.contract_events.len(), 2);
        assert!(tx_response.successful);
    }

    #[test]
    fn tx_response_v3_succeeds_with_none_soroban_meta() {
        let hash = Hash::from([9u8; 32]);
        let response = create_mock_transaction_response_v3(vec![], STATUS_SUCCESS);

        let result = TxResponse::try_from((hash.clone(), response));

        assert!(result.is_ok());
        let tx_response = result.unwrap();
        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert!(tx_response.successful);
        assert!(tx_response.contract_events.is_empty());
    }

    #[test]
    fn tx_response_v3_handles_transaction_status_failed() {
        let hash = Hash::from([10u8; 32]);
        let events = vec![create_mock_contract_event(1)];
        let response = create_mock_transaction_response_v3(events, "FAILED");

        let result = TxResponse::try_from((hash.clone(), response));

        assert!(result.is_ok());
        let tx_response = result.unwrap();
        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert!(!tx_response.successful);
        assert!(tx_response.contract_events.is_empty());
    }

    #[test]
    fn validate_tx_response_with_successful_response() {
        let hash = Hash::from([1u8; 32]);
        let client = create_mock_client();
        let events = vec![vec![create_mock_contract_event(42)]];
        let response = create_mock_transaction_response_v4(events, "SUCCESS");

        let result = client.validate_tx_response(Ok(response), hash.clone());

        assert!(result.is_some());
        let tx_response = result.unwrap();
        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert!(tx_response.successful);
        assert_eq!(tx_response.contract_events.len(), 1);
    }

    #[test]
    fn validate_tx_response_with_rpc_error() {
        let hash = Hash::from([2u8; 32]);
        let rpc_error = stellar_rpc_client::Error::InvalidResponse;
        let client = create_mock_client();

        let result = client.validate_tx_response(Err(rpc_error), hash);

        assert!(result.is_none());
    }

    #[test]
    fn validate_tx_response_with_parse_error() {
        let hash = Hash::from([3u8; 32]);
        let response = create_mock_transaction_response_v4(vec![], "SUCCESS");

        let client = create_mock_client();
        let result = client.validate_tx_response(Ok(response), hash);

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn should_record_rpc_failure_metrics_successfully_when_transaction_responses_fails() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let tx_hash1 =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let tx_hash2 =
            "0000000000000000000000000000000000000000000000000000000000000001".to_string();

        let mut tx_hashes = HashSet::new();

        tx_hashes.insert(tx_hash1.clone());
        tx_hashes.insert(tx_hash2.clone());

        let client = Client::new(
            Url::new_non_sensitive("http://invalid_link").unwrap(),
            monitoring_client,
            ChainName::from_str("stellar").unwrap(),
        )
        .unwrap();

        let result = client.transaction_responses(tx_hashes).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        for _ in 0..2 {
            let msg = receiver.recv().await.unwrap();
            assert_eq!(
                msg,
                Msg::RpcCall {
                    chain_name: ChainName::from_str("stellar").unwrap(),
                    success: false,
                }
            );
        }

        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn should_record_rpc_failure_metrics_successfully_when_transaction_response_fails() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let tx_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let client = Client::new(
            Url::new_non_sensitive("http://invalid_link").unwrap(),
            monitoring_client,
            ChainName::from_str("stellar").unwrap(),
        )
        .unwrap();

        let result = client.transaction_response(tx_hash.clone()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcCall {
                chain_name: ChainName::from_str("stellar").unwrap(),
                success: false,
            }
        );
    }
}

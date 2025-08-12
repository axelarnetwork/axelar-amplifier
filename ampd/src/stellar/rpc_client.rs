use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use error_stack::{report, ResultExt};
use futures::future::join_all;
use stellar_rpc_client::GetTransactionResponse;
use stellar_xdr::curr::{ContractEvent, Hash, TransactionMeta};
use thiserror::Error;
use tracing::warn;

use crate::url::Url;

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
                let contract_events = response.events.contract_events;
                let operation_count = contract_events.len();

                if operation_count != EXPECTED_SOROBAN_OPERATION_COUNT {
                    return Err(TxParseError::InvalidOperationCount {
                        expected: EXPECTED_SOROBAN_OPERATION_COUNT,
                        actual: operation_count,
                    });
                }

                contract_events.into_iter().next().unwrap_or_default()
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

#[cfg_attr(test, faux::create)]
#[derive(Debug)]
pub struct Client(stellar_rpc_client::Client);

#[cfg_attr(test, faux::methods)]
impl Client {
    pub fn new(url: Url) -> error_stack::Result<Self, Error> {
        Ok(Self(
            stellar_rpc_client::Client::new(url.as_str())
                .map_err(|err_str| report!(Error::Client).attach_printable(err_str))?,
        ))
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
                .map(|tx_hash| self.0.get_transaction(tx_hash)),
        )
        .await;

        Ok(responses
            .into_iter()
            .zip(tx_hashes)
            .filter_map(Self::process_transaction_result)
            .collect())
    }

    fn process_transaction_result(
        (response, hash): (
            Result<GetTransactionResponse, stellar_rpc_client::Error>,
            Hash,
        ),
    ) -> Option<(String, TxResponse)> {
        match response {
            Ok(resp) => match TxResponse::try_from((hash, resp)) {
                Ok(tx_response) => Some((tx_response.tx_hash(), tx_response)),
                Err(err) => {
                    warn!(error = %err, "failed to parse transaction response");
                    None
                }
            },
            Err(err) => {
                warn!(error = ?err, "failed to get transaction response");
                None
            }
        }
    }

    pub async fn transaction_response(
        &self,
        tx_hash: String,
    ) -> error_stack::Result<Option<TxResponse>, Error> {
        let tx_hash = Hash::from_str(tx_hash.as_str()).change_context(Error::TxHash)?;

        let response = self.0.get_transaction(&tx_hash).await;
        Ok(Self::process_single_transaction_result((response, tx_hash)))
    }

    fn process_single_transaction_result(
        (response, hash): (
            Result<GetTransactionResponse, stellar_rpc_client::Error>,
            Hash,
        ),
    ) -> Option<TxResponse> {
        let tx_hash = hash.to_string();

        match response {
            Ok(resp) => match TxResponse::try_from((hash, resp)) {
                Ok(tx_response) => Some(tx_response),
                Err(err) => {
                    warn!(
                        error = %err,
                        tx_hash = %tx_hash,
                        "failed to parse transaction response"
                    );
                    None
                }
            },
            Err(err) => {
                warn!(error = ?err, tx_hash = %tx_hash, "failed to get transaction response");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn test_tx_response_v4_succeeds_with_valid_transaction() {
        let hash = Hash::from([5u8; 32]);
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
    fn test_tx_response_v4_handles_transaction_status_failed() {
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
    fn test_tx_response_v4_fails_with_single_empty_operation() {
        let hash = Hash::from([13u8; 32]);
        let response = create_mock_transaction_response_v4(vec![vec![]], STATUS_SUCCESS);

        let result = TxResponse::try_from((hash.clone(), response));

        assert!(result.is_ok());
        let tx_response = result.unwrap();
        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert!(tx_response.successful);
        assert!(tx_response.contract_events.is_empty());
    }

    #[test]
    fn test_tx_response_v4_fails_with_no_operations() {
        let hash = Hash::from([3u8; 32]);
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
    fn test_tx_response_v4_fails_with_multiple_operations() {
        let hash = Hash::from([4u8; 32]);
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
    fn test_tx_response_v3_succeeds_with_valid_transaction() {
        let hash = Hash::from([6u8; 32]);
        let events = vec![create_mock_contract_event(1), create_mock_contract_event(2)];
        let response = create_mock_transaction_response_v3(events, STATUS_SUCCESS);

        let tx_response = TxResponse::try_from((hash.clone(), response)).unwrap();

        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert_eq!(tx_response.contract_events.len(), 2);
        assert!(tx_response.successful);
    }

    #[test]
    fn test_tx_response_v3_handles_transaction_status_failed() {
        let hash = Hash::from([8u8; 32]);
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
    fn test_tx_response_v3_succeeds_with_none_soroban_meta() {
        let hash = Hash::from([12u8; 32]);
        let response = create_mock_transaction_response_v3(vec![], STATUS_SUCCESS);

        let result = TxResponse::try_from((hash.clone(), response));

        assert!(result.is_ok());
        let tx_response = result.unwrap();
        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert!(tx_response.successful);
        assert!(tx_response.contract_events.is_empty());
    }

    #[test]
    fn test_tx_response_fails_with_no_metadata() {
        let hash = Hash::from([9u8; 32]);
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
    fn test_process_transaction_result_returns_failed_transactions() {
        let hash = Hash::from([10u8; 32]);
        let response = create_mock_transaction_response_v4(vec![], "FAILED");
        let rpc_response = Ok(response);

        let result = Client::process_transaction_result((rpc_response, hash.clone()));

        assert!(result.is_some());
        let (tx_hash, tx_response) = result.unwrap();
        assert_eq!(tx_hash, hash.to_string());
        assert!(tx_response.has_failed());
    }

    #[test]
    fn test_failed_transaction_with_wrong_operation_count_v4() {
        let hash = Hash::from([11u8; 32]);
        let response = create_mock_transaction_response_v4(
            vec![
                vec![create_mock_contract_event(1)],
                vec![create_mock_contract_event(2)],
            ],
            "FAILED",
        );
        let rpc_response = Ok(response);

        let result = Client::process_transaction_result((rpc_response, hash.clone()));

        assert!(result.is_some());
        let (tx_hash, tx_response) = result.unwrap();
        assert_eq!(tx_hash, hash.to_string());
        assert!(tx_response.has_failed());
    }
}

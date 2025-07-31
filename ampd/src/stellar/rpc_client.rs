use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use error_stack::{report, ResultExt};
use futures::future::join_all;
use stellar_rpc_client::GetTransactionResponse;
use stellar_xdr::curr::{ContractEvent, Hash};
use thiserror::Error;
use tracing::{debug, error, info, warn};

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
    pub contract_events: Vec<ContractEvent>,
}

const STATUS_SUCCESS: &str = "SUCCESS";

impl From<(Hash, GetTransactionResponse)> for TxResponse {
    fn from((transaction_hash, response): (Hash, GetTransactionResponse)) -> Self {
        // Protocol 23 (CAP-0067): Extract contract events from the unified events structure
        // contract_events is Vec<Vec<ContractEvent>> (per operation), so we flatten it
        let contract_events: Vec<ContractEvent> = response
            .events
            .contract_events
            .into_iter()
            .flatten()
            .collect();

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
pub struct Client(stellar_rpc_client::Client);

#[cfg_attr(test, faux::methods)]
impl Client {
    pub fn new(url: String) -> error_stack::Result<Self, Error> {
        info!(url = %url, "Attempting to create Stellar RPC client");

        // Validate URL format
        if url.is_empty() {
            error!("Stellar RPC URL is empty");
            return Err(report!(Error::Client).attach_printable("URL cannot be empty"));
        }

        match stellar_rpc_client::Client::new(url.as_str()) {
            Ok(client) => {
                info!(url = %url, "Successfully created Stellar RPC client");
                Ok(Self(client))
            }
            Err(err_str) => {
                error!(
                    url = %url,
                    error = %err_str,
                    "Failed to create Stellar RPC client - this could be due to invalid URL, network connectivity issues, or server being unreachable"
                );

                // Add more context about common causes
                let detailed_error = format!(
                    "Failed to create Stellar RPC client for URL '{}'. Error: {}. Common causes: 1) URL is incorrect or malformed, 2) Network connectivity issues, 3) Stellar RPC server is down or unreachable, 4) Firewall blocking the connection, 5) SSL/TLS certificate issues for HTTPS URLs",
                    url, err_str
                );

                Err(report!(Error::Client).attach_printable(detailed_error))
            }
        }
    }

    pub async fn transaction_responses(
        &self,
        tx_hashes: HashSet<String>,
    ) -> error_stack::Result<HashMap<String, TxResponse>, Error> {
        debug!(
            tx_hashes_count = tx_hashes.len(),
            tx_hashes = ?tx_hashes.iter().take(3).collect::<Vec<_>>(),
            "Starting batch transaction responses request to Stellar RPC"
        );

        let tx_hashes: Vec<_> =
            tx_hashes
                .into_iter()
                .map(|tx_hash| {
                    Hash::from_str(tx_hash.as_str()).change_context(Error::TxHash).map_err(|e| {
                    error!(tx_hash = %tx_hash, error = ?e, "Failed to parse transaction hash");
                    e
                })
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;

        debug!(
            tx_hashes_count = tx_hashes.len(),
            "Making concurrent RPC calls to Stellar server"
        );

        let responses = join_all(tx_hashes.iter().enumerate().map(|(i, tx_hash)| {
            debug!(request_index = i, tx_hash = %tx_hash, "Initiating RPC call for transaction");
            self.0.get_transaction(tx_hash)
        }))
        .await;

        let total_responses = responses.len();
        debug!(
            response_count = total_responses,
            "Processing RPC responses from Stellar server"
        );

        let mut successful_responses = 0;
        let mut failed_responses = 0;
        let mut network_errors = 0;
        let mut parsing_errors = 0;

        let result = responses
            .into_iter()
            .zip(tx_hashes)
            .enumerate()
            .filter_map(|(i, (response, hash))| match response {
                Ok(resp) => {
                    successful_responses += 1;
                    debug!(
                        response_index = i,
                        tx_hash = %hash,
                        status = %resp.status,
                        "Successfully received and parsed transaction response"
                    );
                    let tx_response = TxResponse::from((hash, resp));
                    Some((tx_response.tx_hash(), tx_response))
                }
                Err(err) => {
                    failed_responses += 1;

                    // Categorize error types for better debugging
                    let error_type = if err.to_string().contains("connection")
                        || err.to_string().contains("timeout")
                        || err.to_string().contains("network")
                    {
                        network_errors += 1;
                        "NETWORK_ERROR"
                    } else if err.to_string().contains("parse")
                        || err.to_string().contains("json")
                        || err.to_string().contains("deserialize")
                    {
                        parsing_errors += 1;
                        "PARSING_ERROR"
                    } else {
                        "UNKNOWN_ERROR"
                    };

                    error!(
                        response_index = i,
                        tx_hash = %hash,
                        error_type = error_type,
                        error = %err,
                        "Failed to get transaction response from Stellar RPC. Error details: {}",
                        err
                    );
                    None
                }
            })
            .collect::<HashMap<_, _>>();

        info!(
            total_requested = total_responses,
            successful_responses = successful_responses,
            failed_responses = failed_responses,
            network_errors = network_errors,
            parsing_errors = parsing_errors,
            final_result_count = result.len(),
            "Completed batch transaction responses from Stellar RPC"
        );

        if failed_responses > 0 {
            warn!(
                failed_responses = failed_responses,
                success_rate = format!(
                    "{:.1}%",
                    (successful_responses as f64 / total_responses as f64) * 100.0
                ),
                "Some Stellar RPC requests failed - check network connectivity and server status"
            );
        }

        Ok(result)
    }

    pub async fn transaction_response(
        &self,
        tx_hash: String,
    ) -> error_stack::Result<Option<TxResponse>, Error> {
        debug!(tx_hash = %tx_hash, "Requesting single transaction response from Stellar RPC");

        let tx_hash_parsed = Hash::from_str(tx_hash.as_str()).change_context(Error::TxHash).map_err(|e| {
            error!(tx_hash = %tx_hash, error = ?e, "Failed to parse transaction hash for single request");
            e
        })?;

        match self.0.get_transaction(&tx_hash_parsed).await {
            Ok(response) => {
                info!(
                    tx_hash = %tx_hash,
                    status = %response.status,
                    event_count = response.events.contract_events.len(),
                    "Successfully received single transaction response from Stellar RPC"
                );
                Ok(Some(TxResponse::from((tx_hash_parsed, response))))
            }
            Err(err) => {
                // Categorize error for better debugging
                let error_category = if err.to_string().contains("connection")
                    || err.to_string().contains("timeout")
                    || err.to_string().contains("network")
                {
                    "NETWORK_ERROR"
                } else if err.to_string().contains("not found") || err.to_string().contains("404") {
                    "TRANSACTION_NOT_FOUND"
                } else if err.to_string().contains("parse") || err.to_string().contains("json") {
                    "PARSING_ERROR"
                } else {
                    "UNKNOWN_ERROR"
                };

                error!(
                    tx_hash = %tx_hash,
                    error_category = error_category,
                    error = %err,
                    "Failed to get single transaction response from Stellar RPC. Error details: {} | Possible causes: 1) Transaction doesn't exist, 2) Network connectivity issues, 3) RPC server is down, 4) Invalid transaction hash format",
                    err
                );
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use stellar_rpc_client::{GetTransactionEvents, GetTransactionResponse};
    use stellar_xdr::curr::{
        ContractEvent, ContractEventBody, ContractEventType, ContractEventV0, ExtensionPoint, ScVal,
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

    fn create_mock_transaction_response(
        events: Vec<Vec<ContractEvent>>,
        status: &str,
    ) -> GetTransactionResponse {
        GetTransactionResponse {
            status: status.to_string(),
            envelope: None,
            result: None,
            result_meta: None,
            events: GetTransactionEvents {
                contract_events: events,
                diagnostic_events: vec![],
                transaction_events: vec![],
            },
        }
    }

    #[test]
    fn test_tx_response_from_successful_transaction_with_events() {
        let hash = Hash::from([1u8; 32]);
        let contract_events = vec![
            vec![create_mock_contract_event(1), create_mock_contract_event(2)],
            vec![create_mock_contract_event(3)],
        ];
        let response = create_mock_transaction_response(contract_events, STATUS_SUCCESS);

        let tx_response = TxResponse::from((hash.clone(), response));

        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert!(tx_response.successful);
        assert_eq!(tx_response.contract_events.len(), 3); // Flattened: 2 + 1 = 3 events
        assert!(!tx_response.has_failed());
    }

    #[test]
    fn test_tx_response_from_failed_transaction() {
        let hash = Hash::from([2u8; 32]);
        let response = create_mock_transaction_response(vec![], "FAILED");

        let tx_response = TxResponse::from((hash.clone(), response));

        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert!(!tx_response.successful);
        assert!(tx_response.has_failed());
        assert_eq!(tx_response.contract_events.len(), 0);
    }

    #[test]
    fn test_tx_response_from_empty_events() {
        let hash = Hash::from([3u8; 32]);
        let response = create_mock_transaction_response(vec![], STATUS_SUCCESS);

        let tx_response = TxResponse::from((hash.clone(), response));

        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert!(tx_response.successful);
        assert_eq!(tx_response.contract_events.len(), 0);
    }
}

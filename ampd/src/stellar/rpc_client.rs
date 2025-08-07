use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use error_stack::{report, ResultExt};
use futures::future::join_all;
use stellar_rpc_client::GetTransactionResponse;
use stellar_xdr::curr::{ContractEvent, Hash};
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

/// TxResponse parses XDR encoded TransactionMeta to ContractEvent type, and only contains necessary fields for verification
#[derive(Debug)]
pub struct TxResponse {
    pub transaction_hash: String,
    pub successful: bool,
    pub contract_events: Vec<ContractEvent>,
}

const STATUS_SUCCESS: &str = "SUCCESS";
const EXPECTED_OPERATION_COUNT: usize = 1;

impl From<(Hash, GetTransactionResponse)> for TxResponse {
    fn from((transaction_hash, response): (Hash, GetTransactionResponse)) -> Self {
        // Protocol 23: Soroban contract calls can only occur as a single operation in the tx
        // Therefore, we extract the first (and only) operation, otherwise fail.
        let tx_hash_str = transaction_hash.to_string();
        let contract_events: Vec<ContractEvent> = response
            .events
            .contract_events
            .into_iter()
            .flatten()
            .collect();
        let operation_count = contract_events.len();

        if operation_count != EXPECTED_OPERATION_COUNT {
            warn!(
                tx_hash = %tx_hash_str,
                operation_count = operation_count,
                expected_count = EXPECTED_OPERATION_COUNT,
                "Transaction operation count does not match expected single operation for Soroban contract call"
            );
        }

        Self {
            transaction_hash: tx_hash_str,
            successful: (response.status == STATUS_SUCCESS)
                && operation_count == EXPECTED_OPERATION_COUNT,
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
            .filter_map(|(response, hash)| match response {
                Ok(resp) => {
                    let tx_response = TxResponse::from((hash, resp));
                    Some((tx_response.tx_hash(), tx_response))
                }
                Err(err) => {
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

        match self.0.get_transaction(&tx_hash).await {
            Ok(response) => Ok(Some(TxResponse::from((tx_hash, response)))),
            Err(err) => {
                warn!(error = ?err, "failed to get transaction response");
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
    fn test_tx_response_succeeds_with_valid_transaction() {
        let hash = Hash::from([1u8; 32]);
        let contract_events = vec![vec![create_mock_contract_event(1)]];
        let response = create_mock_transaction_response(contract_events, STATUS_SUCCESS);

        let tx_response = TxResponse::from((hash.clone(), response));

        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert_eq!(tx_response.contract_events.len(), 1);
        assert!(tx_response.successful);
    }

    #[test]
    fn test_tx_response_fails_with_failed_transaction() {
        let hash = Hash::from([2u8; 32]);
        let response = create_mock_transaction_response(vec![], "FAILED");

        let tx_response = TxResponse::from((hash.clone(), response));

        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert_eq!(tx_response.contract_events.len(), 0);
        assert!(tx_response.has_failed());
    }

    #[test]
    fn test_tx_response_fails_with_no_operations() {
        let hash = Hash::from([3u8; 32]);
        let response = create_mock_transaction_response(vec![], STATUS_SUCCESS);

        let tx_response = TxResponse::from((hash.clone(), response));

        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert_eq!(tx_response.contract_events.len(), 0);
        assert!(tx_response.has_failed());
    }

    #[test]
    fn test_tx_response_fails_with_multiple_operations() {
        let hash = Hash::from([4u8; 32]);
        let contract_events = vec![
            vec![create_mock_contract_event(1), create_mock_contract_event(2)],
            vec![create_mock_contract_event(3)],
        ];
        let response = create_mock_transaction_response(contract_events, STATUS_SUCCESS);

        let tx_response = TxResponse::from((hash.clone(), response));

        assert_eq!(tx_response.transaction_hash, hash.to_string());
        assert_eq!(tx_response.contract_events.len(), 3);
        assert!(tx_response.has_failed());
    }
}

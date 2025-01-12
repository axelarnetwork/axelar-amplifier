//! Verification implementation of Starknet JSON RPC client's verification of
//! transaction existence

use async_trait::async_trait;
use axelar_wasm_std::msg_id::{Error as MessageFormatError, FieldElementAndEventIndex};
use error_stack::Report;
use mockall::automock;
use starknet_checked_felt::CheckedFelt;
use starknet_core::types::{ExecutionResult, Felt, FromStrError, TransactionReceipt};
use starknet_providers::jsonrpc::JsonRpcTransport;
use starknet_providers::{JsonRpcClient, Provider, ProviderError};
use starknet_types::events::contract_call::ContractCallEvent;
use starknet_types::events::signers_rotated::SignersRotatedEvent;
use thiserror::Error;

type Result<T> = error_stack::Result<T, StarknetClientError>;

#[derive(Debug, Error)]
pub enum StarknetClientError {
    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),
    #[error(transparent)]
    JsonDeserializeError(#[from] serde_json::Error),
    #[error("Failed to fetch tx receipt: {0}")]
    FetchingReceipt(#[from] ProviderError),
    #[error("Failed to create field element from string: {0}")]
    FeltFromString(#[from] FromStrError),
    #[error("Tx not successful")]
    UnsuccessfulTx,
    #[error("u64 overflowed")]
    OverflowingU64,
    #[error("Failed to construct message_id from event: {0}")]
    MessageIdConstruction(#[from] MessageFormatError),
}

/// Implementor of verification method(s) for given network using JSON RPC
/// client.
pub struct Client<T>
where
    T: JsonRpcTransport + Send + Sync,
{
    client: JsonRpcClient<T>,
}

impl<T> Client<T>
where
    T: JsonRpcTransport + Send + Sync,
{
    /// Constructor.
    /// Expects URL of any JSON RPC entry point of Starknet, which you can find
    /// as constants in the `networks.rs` module
    pub fn new_with_transport(transport: T) -> Result<Self> {
        Ok(Client {
            client: JsonRpcClient::new(transport),
        })
    }
}

/// A trait for fetching a ContractCall event, by a given tx_hash
/// and parsing parsing it into
/// `crate::starknet::events::contract_call::ContractCallEvent`
#[automock]
#[async_trait]
pub trait StarknetClient {
    /// Attempts to fetch a ContractCall event, by a given `tx_hash`.
    /// Returns a tuple `(tx_hash, event)` or a `StarknetClientError`.
    async fn get_events_by_hash_contract_call(
        &self,
        tx_hash: CheckedFelt,
    ) -> Result<Vec<(FieldElementAndEventIndex, ContractCallEvent)>>;

    /// Attempts to fetch a SignersRotated event, by a given `tx_hash`.
    /// Returns a tuple `(tx_hash, event)` or a `StarknetClientError`.
    async fn get_event_by_hash_signers_rotated(
        &self,
        tx_hash: CheckedFelt,
    ) -> Result<Option<(Felt, SignersRotatedEvent)>>;
}

#[async_trait]
impl<T> StarknetClient for Client<T>
where
    T: JsonRpcTransport + Send + Sync + 'static,
{
    // Fetches a transaction receipt by hash and extracts one or multiple
    // `ContractCallEvent`
    async fn get_events_by_hash_contract_call(
        &self,
        tx_hash: CheckedFelt,
    ) -> Result<Vec<(FieldElementAndEventIndex, ContractCallEvent)>> {
        let receipt_with_block_info = self
            .client
            .get_transaction_receipt(tx_hash.clone())
            .await
            .map_err(StarknetClientError::FetchingReceipt)?;

        if *receipt_with_block_info.receipt.execution_result() != ExecutionResult::Succeeded {
            return Err(Report::new(StarknetClientError::UnsuccessfulTx));
        }

        let mut message_id_and_event_pairs: Vec<(FieldElementAndEventIndex, ContractCallEvent)> =
            vec![];

        match receipt_with_block_info.receipt {
            TransactionReceipt::Invoke(tx) => {
                let mut event_index: u64 = 0;
                for e in tx.events.clone() {
                    if let Ok(cce) = ContractCallEvent::try_from(e.clone()) {
                        let message_id =
                            FieldElementAndEventIndex::new(tx_hash.clone(), event_index)
                                .map_err(StarknetClientError::MessageIdConstruction)?;
                        message_id_and_event_pairs.push((message_id, cce));
                        event_index = event_index
                            .checked_add(1)
                            .ok_or(StarknetClientError::OverflowingU64)?;
                    }
                }
            }
            TransactionReceipt::L1Handler(_) => (),
            TransactionReceipt::Declare(_) => (),
            TransactionReceipt::Deploy(_) => (),
            TransactionReceipt::DeployAccount(_) => (),
        };

        Ok(message_id_and_event_pairs)
    }

    // Fetches a transaction receipt by hash and extracts a `SignersRotatedEvent` if present
    async fn get_event_by_hash_signers_rotated(
        &self,
        tx_hash: CheckedFelt,
    ) -> Result<Option<(Felt, SignersRotatedEvent)>> {
        let receipt_with_block_info = self
            .client
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(StarknetClientError::FetchingReceipt)?;

        if *receipt_with_block_info.receipt.execution_result() != ExecutionResult::Succeeded {
            return Err(Report::new(StarknetClientError::UnsuccessfulTx));
        }

        let event: Option<(Felt, SignersRotatedEvent)> = match receipt_with_block_info.receipt {
            TransactionReceipt::Invoke(tx) => tx
                .events
                .iter()
                .filter_map(|e| {
                    if let Ok(sre) = SignersRotatedEvent::try_from(e.clone()) {
                        Some((tx.transaction_hash, sre))
                    } else {
                        None
                    }
                })
                .next(),
            TransactionReceipt::L1Handler(_) => None,
            TransactionReceipt::Declare(_) => None,
            TransactionReceipt::Deploy(_) => None,
            TransactionReceipt::DeployAccount(_) => None,
        };

        Ok(event)
    }
}

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use axelar_wasm_std::msg_id::FieldElementAndEventIndex;
    use axum::async_trait;
    use ethers_core::types::H256;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use starknet_checked_felt::CheckedFelt;
    use starknet_core::types::Felt;
    use starknet_providers::jsonrpc::{
        HttpTransportError, JsonRpcMethod, JsonRpcResponse, JsonRpcTransport,
    };
    use starknet_providers::{ProviderError, ProviderRequestData};
    use starknet_types::events::contract_call::ContractCallEvent;
    use starknet_types::events::signers_rotated::SignersRotatedEvent;

    use super::{Client, StarknetClient, StarknetClientError};

    #[tokio::test]
    async fn invalid_signers_rotated_event_tx_fetch() {
        let mock_client =
            Client::new_with_transport(InvalidSignersRotatedEventMockTransport).unwrap();
        let contract_call_event = mock_client
            .get_event_by_hash_signers_rotated(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await;

        assert!(contract_call_event.unwrap().is_none());
    }

    #[tokio::test]
    async fn deploy_account_tx_fetch() {
        let mock_client = Client::new_with_transport(DeployAccountMockTransport).unwrap();
        let contract_call_events = mock_client
            .get_events_by_hash_contract_call(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await;

        assert!(contract_call_events.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deploy_tx_fetch() {
        let mock_client = Client::new_with_transport(DeployMockTransport).unwrap();
        let contract_call_events = mock_client
            .get_events_by_hash_contract_call(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await;

        assert!(contract_call_events.unwrap().is_empty());
    }

    #[tokio::test]
    async fn l1_handler_tx_fetch() {
        let mock_client = Client::new_with_transport(L1HandlerMockTransport).unwrap();
        let contract_call_events = mock_client
            .get_events_by_hash_contract_call(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await;

        assert!(contract_call_events.unwrap().is_empty());
    }

    #[tokio::test]
    async fn declare_tx_fetch() {
        let mock_client = Client::new_with_transport(DeclareMockTransport).unwrap();
        let contract_call_events = mock_client
            .get_events_by_hash_contract_call(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await;

        assert!(contract_call_events.unwrap().is_empty());
    }

    #[tokio::test]
    async fn invalid_contract_call_event_tx_fetch() {
        let mock_client =
            Client::new_with_transport(InvalidContractCallEventMockTransport).unwrap();
        let contract_call_events = mock_client
            .get_events_by_hash_contract_call(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await;

        assert!(contract_call_events.unwrap().is_empty());
    }

    #[tokio::test]
    async fn no_events_tx_fetch() {
        let mock_client = Client::new_with_transport(NoEventsMockTransport).unwrap();
        let contract_call_events = mock_client
            .get_events_by_hash_contract_call(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await;

        assert!(contract_call_events.unwrap().is_empty());
    }

    #[tokio::test]
    async fn reverted_tx_fetch() {
        let mock_client = Client::new_with_transport(RevertedMockTransport).unwrap();
        let contract_call_event = mock_client
            .get_events_by_hash_contract_call(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await;

        assert!(contract_call_event
            .unwrap_err()
            .contains::<StarknetClientError>());
    }

    #[tokio::test]
    async fn failing_tx_fetch() {
        let mock_client = Client::new_with_transport(FailingMockTransport).unwrap();
        let contract_call_event = mock_client
            .get_events_by_hash_contract_call(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await;

        assert!(contract_call_event.is_err());
    }

    #[tokio::test]
    async fn successful_signers_rotated_tx_fetch() {
        let mock_client = Client::new_with_transport(ValidMockTransportSignersRotated).unwrap();
        let signers_rotated_event: (Felt, SignersRotatedEvent) = mock_client
            .get_event_by_hash_signers_rotated(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await
            .unwrap() // unwrap the result
            .unwrap(); // unwrap the option

        assert_eq!(
            signers_rotated_event.0,
            Felt::from_str("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
        );

        let actual: SignersRotatedEvent = signers_rotated_event.1;
        let expected: SignersRotatedEvent = SignersRotatedEvent {
            from_address: "0x2".to_string(),
            epoch: 1,
            signers_hash: [
                226, 62, 119, 4, 210, 79, 100, 110, 94, 54, 44, 97, 64, 122, 105, 210, 212, 32, 63,
                225, 67, 54, 50, 83, 200, 154, 39, 162, 106, 108, 184, 31,
            ],
            signers: starknet_types::events::signers_rotated::WeightedSigners {
                signers: vec![starknet_types::events::signers_rotated::Signer {
                    signer: "0x3ec7d572a0fe479768ac46355651f22a982b99cc".to_string(),
                    weight: 1,
                }],
                threshold: 1,
                nonce: [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 47, 228, 157,
                ],
            },
        };

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn successful_two_call_contracts_in_one_tx_fetch() {
        let mock_client =
            Client::new_with_transport(ValidMockTransportTwoCallContractsInOneTx).unwrap();
        let contract_call_events = mock_client
            .get_events_by_hash_contract_call(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await
            .unwrap(); // unwrap the option

        assert_eq!(
            contract_call_events[0].0,
            FieldElementAndEventIndex::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000001-0"
            )
            .unwrap()
        );
        assert_eq!(
            contract_call_events[0].1,
            ContractCallEvent {
                from_contract_addr:
                    "0x0000000000000000000000000000000000000000000000000000000000000002".to_owned(),
                destination_address: String::from("hello"),
                destination_chain: String::from("destination_chain"),
                source_address: Felt::from_str(
                    "0x00b3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca"
                )
                .unwrap(),
                payload_hash: H256::from_slice(&[
                    28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86,
                    217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200
                ])
            }
        );

        assert_eq!(
            contract_call_events[1].0,
            FieldElementAndEventIndex::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000001-1"
            )
            .unwrap()
        );
        assert_eq!(
            contract_call_events[1].1,
            ContractCallEvent {
                from_contract_addr:
                    "0x0000000000000000000000000000000000000000000000000000000000000002".to_owned(),
                destination_address: String::from("hello"),
                destination_chain: String::from("destination_chain"),
                source_address: Felt::from_str(
                    "0x00b3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca"
                )
                .unwrap(),
                payload_hash: H256::from_slice(&[
                    28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86,
                    217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200
                ])
            }
        );
    }

    #[tokio::test]
    async fn successful_call_contract_tx_fetch() {
        let mock_client = Client::new_with_transport(ValidMockTransportCallContract).unwrap();
        let contract_call_events = mock_client
            .get_events_by_hash_contract_call(
                CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            )
            .await
            .unwrap(); // unwrap the option

        assert_eq!(
            contract_call_events[0].0,
            FieldElementAndEventIndex::from_str(
                "0x0000000000000000000000000000000000000000000000000000000000000001-0"
            )
            .unwrap()
        );
        assert_eq!(
            contract_call_events[0].1,
            ContractCallEvent {
                from_contract_addr:
                    "0x0000000000000000000000000000000000000000000000000000000000000002".to_owned(),
                destination_address: String::from("hello"),
                destination_chain: String::from("destination_chain"),
                source_address: Felt::from_str(
                    "0x00b3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca"
                )
                .unwrap(),
                payload_hash: H256::from_slice(&[
                    28u8, 138, 255, 149, 6, 133, 194, 237, 75, 195, 23, 79, 52, 114, 40, 123, 86,
                    217, 81, 123, 156, 148, 129, 39, 49, 154, 9, 167, 163, 109, 234, 200
                ])
            }
        );
    }

    struct FailingMockTransport;

    #[async_trait]
    impl JsonRpcTransport for FailingMockTransport {
        type Error = ProviderError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            Err(ProviderError::RateLimited)
        }
    }

    struct L1HandlerMockTransport;

    #[async_trait]
    impl JsonRpcTransport for L1HandlerMockTransport {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"L1_HANDLER\",
    \"transaction_hash\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"message_hash\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"SUCCEEDED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }

    struct DeployAccountMockTransport;

    #[async_trait]
    impl JsonRpcTransport for DeployAccountMockTransport {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"DEPLOY_ACCOUNT\",
    \"transaction_hash\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"contract_address\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"SUCCEEDED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }

    struct DeployMockTransport;

    #[async_trait]
    impl JsonRpcTransport for DeployMockTransport {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"DEPLOY\",
    \"transaction_hash\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"contract_address\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"SUCCEEDED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }

    struct DeclareMockTransport;

    #[async_trait]
    impl JsonRpcTransport for DeclareMockTransport {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"DECLARE\",
    \"transaction_hash\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"SUCCEEDED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }

    struct NoEventsMockTransport;

    #[async_trait]
    impl JsonRpcTransport for NoEventsMockTransport {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"INVOKE\",
    \"transaction_hash\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"SUCCEEDED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }

    struct RevertedMockTransport;

    #[async_trait]
    impl JsonRpcTransport for RevertedMockTransport {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"INVOKE\",
    \"transaction_hash\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"REVERTED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }

    struct InvalidSignersRotatedEventMockTransport;

    #[async_trait]
    impl JsonRpcTransport for InvalidSignersRotatedEventMockTransport {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            // garbage "data"
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"INVOKE\",
    \"transaction_hash\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"SUCCEEDED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [
      {
        \"from_address\": \"0x000000000000000000000000000000000000000000000000000000000000002\",
        \"keys\": [
          \"0x01815547484542c49542242a23bc0a1b762af99232f38c0417050825aea8fc93\",
          \"0x0268929df65ee595bb8592323f981351efdc467d564effc6d2e54d2e666e43ca\",
          \"0x01\",
          \"0xd4203fe143363253c89a27a26a6cb81f\",
          \"0xe23e7704d24f646e5e362c61407a69d2\"
        ],
        \"data\": [
            \"0xb3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca\",
            \"0x0000000000000000000000000000000000000000000000000000000000000000\",
            \"0x00000000000000000000000000000000000000000000000000000068656c6c6f\",
            \"0x0000000000000000000000000000000000000000000000000000000000000001\",
            \"0x0000000000000000000000000000000056d9517b9c948127319a09a7a36deac8\",
            \"0x000000000000000000000000000000001c8aff950685c2ed4bc3174f3472287b\",
            \"0x0000000000000000000000000000000000000000000000000000000000000005\",
            \"0x0000000000000000000000000000000000000000000000000000000000000068\",
            \"0x0000000000000000000000000000000000000000000000000000000000000065\",
            \"0x000000000000000000000000000000000000000000000000000000000000006c\",
            \"0x000000000000000000000000000000000000000000000000000000000000006c\",
            \"0x000000000000000000000000000000000000000000000000000000000000006f\"
        ]
      }
    ],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }

    struct InvalidContractCallEventMockTransport;

    #[async_trait]
    impl JsonRpcTransport for InvalidContractCallEventMockTransport {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            // 1 byte for the pending_word, instead of 5
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"INVOKE\",
    \"transaction_hash\": \"0x000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"SUCCEEDED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [
      {
        \"from_address\": \"0x000000000000000000000000000000000000000000000000000000000000002\",
        \"keys\": [
          \"0x01815547484542c49542242a23bc0a1b762af99232f38c0417050825aea8fc93\",
          \"0x0268929df65ee595bb8592323f981351efdc467d564effc6d2e54d2e666e43ca\",
          \"0x01\",
          \"0xd4203fe143363253c89a27a26a6cb81f\",
          \"0xe23e7704d24f646e5e362c61407a69d2\"
        ],
        \"data\": [
            \"0xb3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca\",
            \"0x0000000000000000000000000000000000000000000000000000000000000000\",
            \"0x00000000000000000000000000000000000000000000000000000068656c6c6f\",
            \"0x0000000000000000000000000000000000000000000000000000000000000001\",
            \"0x0000000000000000000000000000000056d9517b9c948127319a09a7a36deac8\",
            \"0x000000000000000000000000000000001c8aff950685c2ed4bc3174f3472287b\",
            \"0x0000000000000000000000000000000000000000000000000000000000000005\",
            \"0x0000000000000000000000000000000000000000000000000000000000000068\",
            \"0x0000000000000000000000000000000000000000000000000000000000000065\",
            \"0x000000000000000000000000000000000000000000000000000000000000006c\",
            \"0x000000000000000000000000000000000000000000000000000000000000006c\",
            \"0x000000000000000000000000000000000000000000000000000000000000006f\"
        ]
      }
    ],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }

    struct ValidMockTransportSignersRotated;

    #[async_trait]
    impl JsonRpcTransport for ValidMockTransportSignersRotated {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"INVOKE\",
    \"transaction_hash\": \"0x0000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"SUCCEEDED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [
      {
        \"from_address\": \"0x0000000000000000000000000000000000000000000000000000000000000002\",
        \"keys\": [
          \"0x01815547484542c49542242a23bc0a1b762af99232f38c0417050825aea8fc93\",
          \"0x0268929df65ee595bb8592323f981351efdc467d564effc6d2e54d2e666e43ca\",
          \"0x01\",
          \"0xd4203fe143363253c89a27a26a6cb81f\",
          \"0xe23e7704d24f646e5e362c61407a69d2\"
        ],
        \"data\": [
            \"0x01\",
            \"0x3ec7d572a0fe479768ac46355651f22a982b99cc\",
            \"0x01\",
            \"0x01\",
            \"0x2fe49d\",
            \"0x00\"
        ]
      }
    ],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }

    struct ValidMockTransportTwoCallContractsInOneTx;

    #[async_trait]
    impl JsonRpcTransport for ValidMockTransportTwoCallContractsInOneTx {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"INVOKE\",
    \"transaction_hash\": \"0x0000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"SUCCEEDED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [
      {
        \"from_address\": \"0x0000000000000000000000000000000000000000000000000000000000000002\",
        \"keys\": [
          \"0x034d074b86d78f064ec0a29639fcfab989c7a3ea6343653633624b2df9ec08f6\",
          \"0x00000000000000000000000000000064657374696e6174696f6e5f636861696e\"
        ],
        \"data\": [
            \"0xb3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca\",
            \"0x0000000000000000000000000000000000000000000000000000000000000000\",
            \"0x00000000000000000000000000000000000000000000000000000068656c6c6f\",
            \"0x0000000000000000000000000000000000000000000000000000000000000005\",
            \"0x0000000000000000000000000000000056d9517b9c948127319a09a7a36deac8\",
            \"0x000000000000000000000000000000001c8aff950685c2ed4bc3174f3472287b\",
            \"0x0000000000000000000000000000000000000000000000000000000000000005\",
            \"0x0000000000000000000000000000000000000000000000000000000000000068\",
            \"0x0000000000000000000000000000000000000000000000000000000000000065\",
            \"0x000000000000000000000000000000000000000000000000000000000000006c\",
            \"0x000000000000000000000000000000000000000000000000000000000000006c\",
            \"0x000000000000000000000000000000000000000000000000000000000000006f\"
        ]
      }, {
        \"from_address\": \"0x0000000000000000000000000000000000000000000000000000000000000002\",
        \"keys\": [
          \"0x034d074b86d78f064ec0a29639fcfab989c7a3ea6343653633624b2df9ec08f6\",
          \"0x00000000000000000000000000000064657374696e6174696f6e5f636861696e\"
        ],
        \"data\": [
            \"0xb3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca\",
            \"0x0000000000000000000000000000000000000000000000000000000000000000\",
            \"0x00000000000000000000000000000000000000000000000000000068656c6c6f\",
            \"0x0000000000000000000000000000000000000000000000000000000000000005\",
            \"0x0000000000000000000000000000000056d9517b9c948127319a09a7a36deac8\",
            \"0x000000000000000000000000000000001c8aff950685c2ed4bc3174f3472287b\",
            \"0x0000000000000000000000000000000000000000000000000000000000000005\",
            \"0x0000000000000000000000000000000000000000000000000000000000000068\",
            \"0x0000000000000000000000000000000000000000000000000000000000000065\",
            \"0x000000000000000000000000000000000000000000000000000000000000006c\",
            \"0x000000000000000000000000000000000000000000000000000000000000006c\",
            \"0x000000000000000000000000000000000000000000000000000000000000006f\"
        ]
      }
    ],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }
    struct ValidMockTransportCallContract;

    #[async_trait]
    impl JsonRpcTransport for ValidMockTransportCallContract {
        type Error = HttpTransportError;

        async fn send_requests<R>(
            &self,
            _requests: R,
        ) -> Result<Vec<JsonRpcResponse<serde_json::Value>>, Self::Error>
        where
            R: AsRef<[ProviderRequestData]> + Send + Sync,
        {
            unimplemented!();
        }

        async fn send_request<P, R>(
            &self,
            _method: JsonRpcMethod,
            _params: P,
        ) -> Result<JsonRpcResponse<R>, Self::Error>
        where
            P: Serialize + Send + Sync,
            R: DeserializeOwned,
        {
            let response_mock = "{
  \"jsonrpc\": \"2.0\",
  \"result\": {
    \"type\": \"INVOKE\",
    \"transaction_hash\": \"0x0000000000000000000000000000000000000000000000000000000000000001\",
    \"actual_fee\": {
      \"amount\": \"0x3062e4c46d4\",
      \"unit\": \"WEI\"
    },
    \"execution_status\": \"SUCCEEDED\",
    \"finality_status\": \"ACCEPTED_ON_L2\",
    \"block_hash\": \"0x5820e3a0aaceebdbda0b308fdf666eff64f263f6ed8ee74d6f78683b65a997b\",
    \"block_number\": 637493,
    \"messages_sent\": [],
    \"events\": [
      {
        \"from_address\": \"0x0000000000000000000000000000000000000000000000000000000000000002\",
        \"keys\": [
          \"0x034d074b86d78f064ec0a29639fcfab989c7a3ea6343653633624b2df9ec08f6\",
          \"0x00000000000000000000000000000064657374696e6174696f6e5f636861696e\"
        ],
        \"data\": [
            \"0xb3ff441a68610b30fd5e2abbf3a1548eb6ba6f3559f2862bf2dc757e5828ca\",
            \"0x0000000000000000000000000000000000000000000000000000000000000000\",
            \"0x00000000000000000000000000000000000000000000000000000068656c6c6f\",
            \"0x0000000000000000000000000000000000000000000000000000000000000005\",
            \"0x0000000000000000000000000000000056d9517b9c948127319a09a7a36deac8\",
            \"0x000000000000000000000000000000001c8aff950685c2ed4bc3174f3472287b\",
            \"0x0000000000000000000000000000000000000000000000000000000000000005\",
            \"0x0000000000000000000000000000000000000000000000000000000000000068\",
            \"0x0000000000000000000000000000000000000000000000000000000000000065\",
            \"0x000000000000000000000000000000000000000000000000000000000000006c\",
            \"0x000000000000000000000000000000000000000000000000000000000000006c\",
            \"0x000000000000000000000000000000000000000000000000000000000000006f\"
        ]
      }
    ],
    \"execution_resources\": {
      \"data_availability\": {
        \"l1_data_gas\": 0,
        \"l1_gas\": 0
      },
      \"memory_holes\": 1176,
      \"pedersen_builtin_applications\": 34,
      \"range_check_builtin_applications\": 1279,
      \"steps\": 17574
    }
  },
  \"id\": 0
}";
            let parsed_response = serde_json::from_str(response_mock).map_err(Self::Error::Json)?;

            Ok(parsed_response)
        }
    }
}

//! Verification implementation of Starknet JSON RPC client's verification of
//! transaction existence

use async_trait::async_trait;
use error_stack::Report;
use mockall::automock;
use starknet_core::types::{ExecutionResult, Felt, FromStrError, TransactionReceipt};
use starknet_providers::jsonrpc::JsonRpcTransport;
use starknet_providers::{JsonRpcClient, Provider, ProviderError};
use starknet_types::events::contract_call::ContractCallEvent;
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
}

/// Implementor of verification method(s) for given network using JSON RPC
/// client.
pub struct Client<T>
where
    T: JsonRpcTransport + Send + Sync + 'static,
{
    client: JsonRpcClient<T>,
}

impl<T> Client<T>
where
    T: JsonRpcTransport + Send + Sync + 'static,
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
    async fn get_event_by_hash(&self, tx_hash: Felt) -> Result<Option<(Felt, ContractCallEvent)>>;
}

#[async_trait]
impl<T> StarknetClient for Client<T>
where
    T: JsonRpcTransport + Send + Sync + 'static,
{
    async fn get_event_by_hash(&self, tx_hash: Felt) -> Result<Option<(Felt, ContractCallEvent)>> {
        // TODO: Check ACCEPTED ON L1 times and decide if we should use it
        //
        // Finality status is always at least ACCEPTED_ON_L2 and this is what we're
        // looking for, because ACCEPTED_ON_L1 (Ethereum) will take a very long time.
        //
        // Check https://github.com/eigerco/giza-axelar-starknet/issues/90
        let receipt_with_block_info = self
            .client
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(StarknetClientError::FetchingReceipt)?;

        if *receipt_with_block_info.receipt.execution_result() != ExecutionResult::Succeeded {
            return Err(Report::new(StarknetClientError::UnsuccessfulTx));
        }

        let event: Option<(Felt, ContractCallEvent)> = match receipt_with_block_info.receipt {
            TransactionReceipt::Invoke(tx) => {
                // NOTE: There should be only one ContractCall event per gateway tx
                tx.events
                    .iter()
                    .filter_map(|e| {
                        // NOTE: Here we ignore the error, because the event might
                        // not be ContractCall and that by itself is not erroneous behavior
                        if let Ok(cce) = ContractCallEvent::try_from(e.clone()) {
                            Some((tx.transaction_hash, cce))
                        } else {
                            None
                        }
                    })
                    .next()
            }
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

    use axum::async_trait;
    use ethers_core::types::H256;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use starknet_core::types::Felt;
    use starknet_providers::jsonrpc::{
        HttpTransportError, JsonRpcMethod, JsonRpcResponse, JsonRpcTransport,
    };
    use starknet_providers::{ProviderError, ProviderRequestData};
    use starknet_types::events::contract_call::ContractCallEvent;

    use super::{Client, StarknetClient, StarknetClientError};

    #[tokio::test]
    async fn deploy_account_tx_fetch() {
        let mock_client = Client::new_with_transport(DeployAccountMockTransport).unwrap();
        let contract_call_event = mock_client.get_event_by_hash(Felt::ONE).await;

        assert!(contract_call_event.unwrap().is_none());
    }

    #[tokio::test]
    async fn deploy_tx_fetch() {
        let mock_client = Client::new_with_transport(DeployMockTransport).unwrap();
        let contract_call_event = mock_client.get_event_by_hash(Felt::ONE).await;

        assert!(contract_call_event.unwrap().is_none());
    }

    #[tokio::test]
    async fn l1_handler_tx_fetch() {
        let mock_client = Client::new_with_transport(L1HandlerMockTransport).unwrap();
        let contract_call_event = mock_client.get_event_by_hash(Felt::ONE).await;

        assert!(contract_call_event.unwrap().is_none());
    }

    #[tokio::test]
    async fn declare_tx_fetch() {
        let mock_client = Client::new_with_transport(DeclareMockTransport).unwrap();
        let contract_call_event = mock_client.get_event_by_hash(Felt::ONE).await;

        assert!(contract_call_event.unwrap().is_none());
    }

    #[tokio::test]
    async fn invalid_contract_call_event_tx_fetch() {
        let mock_client =
            Client::new_with_transport(InvalidContractCallEventMockTransport).unwrap();
        let contract_call_event = mock_client.get_event_by_hash(Felt::ONE).await;

        assert!(contract_call_event.unwrap().is_none());
    }

    #[tokio::test]
    async fn no_events_tx_fetch() {
        let mock_client = Client::new_with_transport(NoEventsMockTransport).unwrap();
        let contract_call_event = mock_client.get_event_by_hash(Felt::ONE).await;

        assert!(contract_call_event.unwrap().is_none());
    }

    #[tokio::test]
    async fn reverted_tx_fetch() {
        let mock_client = Client::new_with_transport(RevertedMockTransport).unwrap();
        let contract_call_event = mock_client.get_event_by_hash(Felt::ONE).await;

        assert!(contract_call_event
            .unwrap_err()
            .contains::<StarknetClientError>());
    }

    #[tokio::test]
    async fn failing_tx_fetch() {
        let mock_client = Client::new_with_transport(FailingMockTransport).unwrap();
        let contract_call_event = mock_client.get_event_by_hash(Felt::ONE).await;

        assert!(contract_call_event.is_err());
    }

    #[tokio::test]
    async fn successful_tx_fetch() {
        let mock_client = Client::new_with_transport(ValidMockTransport).unwrap();
        let contract_call_event = mock_client
            .get_event_by_hash(Felt::ONE)
            .await
            .unwrap() // unwrap the result
            .unwrap(); // unwrap the option

        assert_eq!(
            contract_call_event.0,
            Felt::from_str("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
        );
        assert_eq!(
            contract_call_event.1,
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
          \"0x034d074b86d78f064ec0a29639fcfab989c7a3ea6343653633624b2df9ec08f6\",
          \"0x00000000000000000000000000000064657374696e6174696f6e5f636861696e\"
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

    struct ValidMockTransport;

    #[async_trait]
    impl JsonRpcTransport for ValidMockTransport {
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

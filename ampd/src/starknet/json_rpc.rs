//! Verification implementation of Starknet JSON RPC client's verification of
//! transaction existence

use std::fmt;

use async_trait::async_trait;
use axelar_wasm_std::msg_id::FieldElementAndEventIndex;
use mockall::automock;
use router_api::ChainName;
use starknet_core::types::{ExecutionResult, TransactionReceipt};
use starknet_providers::jsonrpc::JsonRpcTransport;
use starknet_providers::{JsonRpcClient, Provider, ProviderError};
use thiserror::Error;

use crate::monitoring;
use crate::monitoring::metrics::Msg;
use crate::types::starknet::events::contract_call::{ContractCallError, ContractCallEvent};
use crate::types::starknet::events::signers_rotated::SignersRotatedEvent;

type Result<T> = error_stack::Result<T, StarknetClientError>;

#[derive(Debug, Error)]
pub enum StarknetClientError {
    #[error(transparent)]
    ContractCallError(#[from] ContractCallError),
    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),
    #[error(transparent)]
    JsonDeserializeError(#[from] serde_json::Error),
    #[error("Failed to fetch tx receipt: {0}")]
    FetchingReceipt(#[from] ProviderError),
}

/// Implementor of verification method(s) for given network using JSON RPC
/// client.
pub struct Client<T>
where
    T: JsonRpcTransport + Send + Sync,
{
    client: JsonRpcClient<T>,
    monitoring_client: monitoring::Client,
    chain_name: ChainName,
}

impl<T> Client<T>
where
    T: JsonRpcTransport + Send + Sync,
{
    /// Constructor.
    /// Expects URL of any JSON RPC entry point of Starknet, which you can find
    /// as constants in the `networks.rs` module
    pub fn new_with_transport(
        client: T,
        monitoring_client: monitoring::Client,
        chain_name: ChainName,
    ) -> Result<Self> {
        Ok(Client {
            client: JsonRpcClient::new(client),
            monitoring_client,
            chain_name,
        })
    }
}

/// A trait for fetching a ContractCall event, by a given tx_hash
/// and parsing parsing it into
/// `crate::starknet::events::contract_call::ContractCallEvent`
#[automock]
#[async_trait]
pub trait StarknetClient {
    /// Attempts to fetch a ContractCall event, by a given `message_id`.
    /// Returns the event or a `StarknetClientError`.
    async fn event_by_message_id_contract_call(
        &self,
        message_id: FieldElementAndEventIndex,
    ) -> Option<ContractCallEvent>;

    /// Attempts to fetch a SignersRotated event, by a given `tx_hash`.
    /// Returns a tuple `(tx_hash, event)` or a `StarknetClientError`.
    async fn event_by_message_id_signers_rotated(
        &self,
        message_id: FieldElementAndEventIndex,
    ) -> Option<SignersRotatedEvent>;
}

#[async_trait]
impl<T> StarknetClient for Client<T>
where
    T: JsonRpcTransport + Send + Sync + 'static,
{
    // Fetches a transaction receipt by hash and extracts one or multiple
    // `ContractCallEvent`
    async fn event_by_message_id_contract_call(
        &self,
        message_id: FieldElementAndEventIndex,
    ) -> Option<ContractCallEvent> {
        let receipt_with_block_info = self
            .client
            .get_transaction_receipt(message_id.tx_hash.clone())
            .await
            .inspect_err(|_| {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::RpcError {
                        chain_name: self.chain_name.clone(),
                    });
            })
            .ok()?;

        if *receipt_with_block_info.receipt.execution_result() != ExecutionResult::Succeeded {
            return None;
        }

        match receipt_with_block_info.receipt {
            TransactionReceipt::Invoke(tx) => {
                let event_index: usize = message_id.event_index.try_into().ok()?;
                let event = tx.events.get(event_index)?;

                ContractCallEvent::try_from(event.clone()).ok()
            }
            _ => None,
        }
    }

    // Fetches a transaction receipt by hash and extracts a `SignersRotatedEvent` if present
    async fn event_by_message_id_signers_rotated(
        &self,
        message_id: FieldElementAndEventIndex,
    ) -> Option<SignersRotatedEvent> {
        let receipt_with_block_info = self
            .client
            .get_transaction_receipt(message_id.tx_hash.clone())
            .await
            .inspect_err(|_| {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::RpcError {
                        chain_name: self.chain_name.clone(),
                    });
            })
            .ok()?;

        if *receipt_with_block_info.receipt.execution_result() != ExecutionResult::Succeeded {
            return None;
        };

        // get event from receipt by index
        match receipt_with_block_info.receipt {
            TransactionReceipt::Invoke(tx) => {
                let event_index: usize = message_id.event_index.try_into().ok()?;
                let event = tx.events.get(event_index)?;

                SignersRotatedEvent::try_from(event.clone()).ok()
            }
            _ => None,
        }
    }
}

impl<T> fmt::Debug for Client<T>
where
    T: JsonRpcTransport + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let client = "redacted".to_string();
        f.debug_struct("Client").field("client", &client).finish()
    }
}

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use axelar_wasm_std::msg_id::FieldElementAndEventIndex;
    use axum::async_trait;
    use ethers_core::types::H256;
    use router_api::ChainName;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use starknet_checked_felt::CheckedFelt;
    use starknet_core::types::Felt;
    use starknet_providers::jsonrpc::{
        HttpTransportError, JsonRpcMethod, JsonRpcResponse, JsonRpcTransport,
    };
    use starknet_providers::{ProviderError, ProviderRequestData};

    use super::{Client, StarknetClient};
    use crate::monitoring::metrics::Msg;
    use crate::monitoring::test_utils;
    use crate::types::starknet::events::contract_call::ContractCallEvent;
    use crate::types::starknet::events::signers_rotated::SignersRotatedEvent;

    #[tokio::test]
    async fn invalid_signers_rotated_event_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            InvalidSignersRotatedEventMockTransport,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_event = mock_client
            .event_by_message_id_signers_rotated(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await;

        assert!(contract_call_event.is_none());
    }

    #[tokio::test]
    async fn deploy_account_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            DeployAccountMockTransport,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_events = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await;

        assert!(contract_call_events.is_none());
    }

    #[tokio::test]
    async fn deploy_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            DeployMockTransport,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_events = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await;

        assert!(contract_call_events.is_none());
    }

    #[tokio::test]
    async fn l1_handler_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            L1HandlerMockTransport,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_events = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await;

        assert!(contract_call_events.is_none());
    }

    #[tokio::test]
    async fn declare_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            DeclareMockTransport,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_events = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await;

        assert!(contract_call_events.is_none());
    }

    #[tokio::test]
    async fn invalid_contract_call_event_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            InvalidContractCallEventMockTransport,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_events = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await;

        assert!(contract_call_events.is_none());
    }

    #[tokio::test]
    async fn no_events_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            NoEventsMockTransport,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_events = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await;

        assert!(contract_call_events.is_none());
    }

    #[tokio::test]
    async fn reverted_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            RevertedMockTransport,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_event = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await;

        assert!(contract_call_event.is_none())
    }

    #[tokio::test]
    async fn failing_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            FailingMockTransport,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_event = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await;

        assert!(contract_call_event.is_none());
    }

    #[tokio::test]
    async fn successful_signers_rotated_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            ValidMockTransportSignersRotated,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let signers_rotated_event = mock_client
            .event_by_message_id_signers_rotated(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await
            .unwrap();

        assert_eq!(signers_rotated_event.from_address, "0x2".to_string());

        let expected: SignersRotatedEvent = SignersRotatedEvent {
            from_address: "0x2".to_string(),
            epoch: 1,
            signers_hash: [
                226, 62, 119, 4, 210, 79, 100, 110, 94, 54, 44, 97, 64, 122, 105, 210, 212, 32, 63,
                225, 67, 54, 50, 83, 200, 154, 39, 162, 106, 108, 184, 31,
            ],
            signers: crate::types::starknet::events::signers_rotated::WeightedSigners {
                signers: vec![crate::types::starknet::events::signers_rotated::Signer {
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

        assert_eq!(signers_rotated_event, expected);
    }

    #[tokio::test]
    async fn successful_two_call_contracts_in_one_tx_fetch() {
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            ValidMockTransportTwoCallContractsInOneTx,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_events = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await
            .unwrap(); // unwrap the option

        assert_eq!(
            contract_call_events,
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

        let contract_call_events_1 = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 1,
            })
            .await
            .unwrap(); // unwrap the option

        assert_eq!(
            contract_call_events_1,
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
        let (monitoring_client, _) = test_utils::monitoring_client();
        let mock_client = Client::new_with_transport(
            ValidMockTransportCallContract,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();
        let contract_call_events = mock_client
            .event_by_message_id_contract_call(FieldElementAndEventIndex {
                tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
                event_index: 0,
            })
            .await
            .unwrap(); // unwrap the option

        assert_eq!(
            contract_call_events,
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
    async fn should_record_rpc_error_metrics_when_rpc_fails() {
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();

        let client = Client::new_with_transport(
            FailingMockTransport,
            monitoring_client,
            ChainName::from_str("starknet").unwrap(),
        )
        .unwrap();

        let message_id = FieldElementAndEventIndex {
            tx_hash: CheckedFelt::try_from(&Felt::ONE.to_bytes_be()).unwrap(),
            event_index: 0,
        };

        let result = client
            .event_by_message_id_contract_call(message_id.clone())
            .await;
        assert!(result.is_none());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcError {
                chain_name: ChainName::from_str("starknet").unwrap(),
            }
        );

        let result = client.event_by_message_id_signers_rotated(message_id).await;
        assert!(result.is_none());

        let msg = receiver.recv().await.unwrap();
        assert_eq!(
            msg,
            Msg::RpcError {
                chain_name: ChainName::from_str("starknet").unwrap(),
            }
        );

        assert!(receiver.try_recv().is_err());
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

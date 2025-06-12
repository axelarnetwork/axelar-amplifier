use std::pin::Pin;
use std::vec;

use ampd_proto;
use ampd_proto::blockchain_service_client::BlockchainServiceClient;
use ampd_proto::crypto_service_client::CryptoServiceClient;
use ampd_proto::{
    AddressRequest, BroadcastRequest, BroadcastResponse, ContractStateRequest, ContractsRequest,
    ContractsResponse, KeyId, KeyRequest, SignRequest, SubscribeRequest,
};
use async_trait::async_trait;
use axelar_wasm_std::nonempty;
use cosmrs::AccountId;
use error_stack::{bail, Report, Result, ResultExt as _};
use events::{AbciEventTypeFilter, Event};
use futures::StreamExt;
use mockall::automock;
use report::{ResultCompatExt, ResultExt};
use serde::de::DeserializeOwned;
use tokio_stream::Stream;
use tonic::{transport, Request};

use crate::grpc::error::{AppError, Error};

#[automock(type Stream = tokio_stream::Iter<vec::IntoIter<Result<Event, Error>>>;)]
#[async_trait]
pub trait Client {
    type Stream: Stream<Item = Result<Event, Error>>;

    async fn subscribe(
        &mut self,
        filters: Vec<AbciEventTypeFilter>,
        include_block_begin_end: bool,
    ) -> Result<Self::Stream, Error>;

    async fn address(&mut self) -> Result<AccountId, Error>;

    async fn broadcast(&mut self, msg: cosmrs::Any) -> Result<BroadcastClientResponse, Error>;

    async fn contract_state<T: DeserializeOwned + 'static>(
        &mut self,
        contract: nonempty::String,
        query: nonempty::Vec<u8>,
    ) -> Result<T, Error>;

    async fn contracts(&mut self) -> Result<ContractsAddresses, Error>;

    async fn sign(
        &mut self,
        key: Option<Key>,
        message: nonempty::Vec<u8>,
    ) -> Result<nonempty::Vec<u8>, Error>;

    async fn key(&mut self, key: Option<Key>) -> Result<nonempty::Vec<u8>, Error>;
}

#[derive(Clone)]
pub struct GrpcClient {
    pub blockchain: BlockchainServiceClient<transport::Channel>,
    pub crypto: CryptoServiceClient<transport::Channel>,
}

pub async fn new(url: &str) -> Result<GrpcClient, Error> {
    let endpoint: transport::Endpoint = url.parse().into_report()?;
    let conn = endpoint.connect().await.into_report()?;
    let blockchain = BlockchainServiceClient::new(conn.clone());
    let crypto = CryptoServiceClient::new(conn);
    Ok(GrpcClient { blockchain, crypto })
}

#[derive(Debug, Clone, PartialEq)]
pub struct BroadcastClientResponse {
    pub tx_hash: String,
    pub index: u64,
}

impl From<BroadcastResponse> for BroadcastClientResponse {
    fn from(response: BroadcastResponse) -> Self {
        BroadcastClientResponse {
            tx_hash: response.tx_hash,
            index: response.index,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContractsAddresses {
    pub voting_verifier: AccountId,
    pub multisig_prover: AccountId,
    pub service_registry: AccountId,
    pub rewards: AccountId,
}

impl TryFrom<&ContractsResponse> for ContractsAddresses {
    type Error = Report<Error>;

    fn try_from(
        response: &ContractsResponse,
    ) -> core::result::Result<ContractsAddresses, Self::Error> {
        let ContractsResponse {
            voting_verifier,
            multisig_prover,
            service_registry,
            rewards,
        } = response;

        Ok(ContractsAddresses {
            voting_verifier: parse_addr(voting_verifier, "voting verifier")?,
            multisig_prover: parse_addr(multisig_prover, "multisig prover")?,
            service_registry: parse_addr(service_registry, "service registry")?,
            rewards: parse_addr(rewards, "rewards contract")?,
        })
    }
}

fn parse_addr(addr: &str, address_name: &'static str) -> Result<AccountId, Error> {
    addr.parse::<AccountId>()
        .change_context(AppError::InvalidAddress(address_name).into())
        .attach_printable_lazy(|| addr.to_string())
}

pub enum KeyAlgorithm {
    Ecdsa,
    Ed25519,
}

pub struct Key {
    pub id: nonempty::String,
    pub algorithm: KeyAlgorithm,
}

impl From<Key> for KeyId {
    fn from(key: Key) -> Self {
        let algorithm = match key.algorithm {
            KeyAlgorithm::Ecdsa => ampd_proto::Algorithm::Ecdsa,
            KeyAlgorithm::Ed25519 => ampd_proto::Algorithm::Ed25519,
        };

        KeyId {
            id: key.id.into(),
            algorithm: algorithm as i32,
        }
    }
}

#[async_trait]
impl Client for GrpcClient {
    type Stream = Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>;

    async fn subscribe(
        &mut self,
        filters: Vec<AbciEventTypeFilter>,
        include_block_begin_end: bool,
    ) -> Result<Self::Stream, Error> {
        let request = SubscribeRequest {
            filters: filters
                .into_iter()
                .map(|filter| ampd_proto::EventFilter {
                    r#type: filter.event_type,
                    contract: Default::default(),
                })
                .collect(),
            include_block_begin_end,
        };

        let streaming_response = self.blockchain.subscribe(request).await.into_report()?;

        let transformed_stream = streaming_response.into_inner().map(|result| match result {
            Ok(response) => match response.event {
                Some(event) => {
                    Event::try_from(event).change_context(AppError::EventConversion.into())
                }
                None => bail!(Error::from(AppError::InvalidResponse)),
            },
            Err(status) => bail!(Error::from(status)),
        });

        Ok(Box::pin(transformed_stream))
    }

    async fn address(&mut self) -> Result<AccountId, Error> {
        let broadcaster_address = self
            .blockchain
            .address(Request::new(AddressRequest {}))
            .await
            .into_report()?
            .into_inner()
            .address;

        let ampd_broadcaster_address = parse_addr(&broadcaster_address, "broadcaster")?;
        Ok(ampd_broadcaster_address)
    }

    async fn broadcast(&mut self, msg: cosmrs::Any) -> Result<BroadcastClientResponse, Error> {
        let request = BroadcastRequest { msg: Some(msg) };

        let broadcast_response = self
            .blockchain
            .broadcast(request)
            .await
            .into_report()?
            .into_inner();

        Ok(broadcast_response.into())
    }

    async fn contract_state<T: DeserializeOwned + 'static>(
        &mut self,
        contract: nonempty::String,
        query: nonempty::Vec<u8>,
    ) -> Result<T, Error> {
        self.blockchain
            .contract_state(ContractStateRequest {
                contract: contract.into(),
                query: query.into(),
            })
            .await
            .into_report()
            .map(|response| response.into_inner().result)
            .and_then(|result| {
                serde_json::from_slice(&result)
                    .change_context(AppError::InvalidJson.into())
                    .attach_printable(hex::encode(&result))
            })
    }

    async fn contracts(&mut self) -> Result<ContractsAddresses, Error> {
        let response = self
            .blockchain
            .contracts(Request::new(ContractsRequest {}))
            .await
            .into_report()?
            .into_inner();

        ContractsAddresses::try_from(&response)
            .change_context(AppError::InvalidContractsResponse.into())
            .attach_printable(format!("{response:?}"))
    }

    async fn sign(
        &mut self,
        key: Option<Key>,
        message: nonempty::Vec<u8>,
    ) -> Result<nonempty::Vec<u8>, Error> {
        self.crypto
            .sign(Request::new(SignRequest {
                key_id: key.map(|k| k.into()),
                msg: message.into(),
            }))
            .await
            .into_report()
            .and_then(|response| {
                nonempty::Vec::try_from(response.into_inner().signature)
                    .change_context(AppError::InvalidByteArray.into())
            })
    }

    async fn key(&mut self, key: Option<Key>) -> Result<nonempty::Vec<u8>, Error> {
        self.crypto
            .key(Request::new(KeyRequest {
                key_id: key.map(|k| k.into()),
            }))
            .await
            .into_report()
            .and_then(|response| {
                nonempty::Vec::try_from(response.into_inner().pub_key)
                    .change_context(AppError::InvalidByteArray.into())
            })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axelar_wasm_std::nonempty;
    use cosmrs::{AccountId, Any};
    use events::Event;
    use serde_json::Value;
    use tokio_stream::StreamExt;

    use super::*;
    use crate::grpc::error::GrpcError;

    #[tokio::test]
    async fn address_should_succeed_returning_the_address() {
        let mut mock = MockClient::new();
        let expected_address = sample_account_id();

        mock.expect_address().return_once({
            let addr = expected_address.clone();
            move || Ok(addr.clone())
        });

        let result = mock.address().await;
        assert!(result.is_ok_and(|address| address == expected_address));
    }

    #[tokio::test]
    async fn address_should_return_error_if_grpc_error_occurs() {
        let mut mock = MockClient::new();

        mock.expect_address().return_once(|| {
            Err(Report::new(
                GrpcError::ServiceUnavailable("service unavailable".to_string()).into(),
            ))
        });

        let result = mock.address().await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::Grpc(GrpcError::ServiceUnavailable(_))
        )));
    }

    #[tokio::test]
    async fn address_should_return_error_if_invalid_argument_is_provided() {
        let mut mock = MockClient::new();

        mock.expect_address().return_once(|| {
            Err(Report::new(
                GrpcError::InvalidArgument("invalid request".to_string()).into(),
            ))
        });

        let result = mock.address().await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::Grpc(GrpcError::InvalidArgument(_))
        )));
    }

    #[tokio::test]
    async fn address_should_handle_multiple_consecutive_calls() {
        let mut mock = MockClient::new();
        let expected_address = sample_account_id();

        mock.expect_address().times(5).returning({
            let addr = expected_address.clone();
            move || Ok(addr.clone())
        });

        for _ in 0..5 {
            let result = mock.address().await;
            assert!(result.is_ok_and(|address| address == expected_address));
        }
    }

    #[tokio::test]
    async fn broadcast_should_succeed_returning_the_response() {
        let mut mock = MockClient::new();
        let expected_response = sample_broadcast_response();

        mock.expect_broadcast().return_once({
            let response = expected_response.clone();
            move |_| Ok(response.clone())
        });

        let result = mock.broadcast(any_msg()).await;
        assert!(result.is_ok_and(|response| response == expected_response));
    }

    #[tokio::test]
    async fn broadcast_should_return_error_if_internal_error_occurs() {
        let mut mock = MockClient::new();

        mock.expect_broadcast().return_once(|_| {
            Err(Report::new(
                GrpcError::InternalError("gas estimation failed".to_string()).into(),
            ))
        });

        let result = mock.broadcast(any_msg()).await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::Grpc(GrpcError::InternalError(_))
        )));
    }

    #[tokio::test]
    async fn broadcast_should_handle_empty_message_value() {
        let mut mock = MockClient::new();

        mock.expect_broadcast()
            .return_once(|_| Ok(sample_broadcast_response()));

        let empty_msg = Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![],
        };

        let result = mock.broadcast(empty_msg).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn contract_state_should_succeed_returning_the_response() {
        let mut mock = MockClient::new();

        #[derive(serde::Deserialize, Debug, PartialEq, Clone)]
        struct TestResponse {
            balance: String,
            owner: String,
        }

        let expected_response = TestResponse {
            balance: "1000".to_string(),
            owner: "axelar1abc".to_string(),
        };

        mock.expect_contract_state::<TestResponse>().return_once({
            let response = expected_response.clone();
            move |_, _| Ok(response.clone())
        });
        let (contract, query) = contract_state_input_args();

        let result: Result<TestResponse, Error> = mock.contract_state(contract, query).await;
        assert!(result.is_ok_and(|response| response == expected_response));
    }

    #[tokio::test]
    async fn contract_state_should_return_error_if_invalid_response() {
        let mut mock = MockClient::new();

        mock.expect_contract_state::<Value>()
            .return_once(|_, _| Err(Report::new(AppError::InvalidJson.into())));

        let (contract, query) = contract_state_input_args();

        let result: Result<Value, Error> = mock.contract_state(contract, query).await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::App(AppError::InvalidJson)
        )));
    }

    #[tokio::test]
    async fn contract_state_should_return_error_if_operation_failed() {
        let mut mock = MockClient::new();

        mock.expect_contract_state::<Value>().return_once(|_, _| {
            Err(Report::new(
                GrpcError::OperationFailed("contract execution failed".to_string()).into(),
            ))
        });

        let (contract, query) = contract_state_input_args();

        let result: Result<Value, Error> = mock.contract_state(contract, query).await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::Grpc(GrpcError::OperationFailed(_))
        )));
    }

    #[tokio::test]
    async fn contracts_should_succeed_returning_the_response() {
        let mut mock = MockClient::new();
        let expected_contracts = sample_contracts();

        mock.expect_contracts().return_once({
            let contracts = expected_contracts.clone();
            move || Ok(contracts.clone())
        });

        let result = mock.contracts().await;
        assert!(result.is_ok_and(|contracts| contracts == expected_contracts));
    }

    #[tokio::test]
    async fn contracts_should_return_error_if_invalid_contracts_response() {
        let mut mock = MockClient::new();

        mock.expect_contracts()
            .return_once(|| Err(Report::new(AppError::InvalidContractsResponse.into())));

        let result = mock.contracts().await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::App(AppError::InvalidContractsResponse)
        )));
    }

    #[tokio::test]
    async fn sign_should_succeed_returning_the_signature() {
        let mut mock = MockClient::new();
        let expected_signature = sample_signature();

        mock.expect_sign().return_once({
            let sig = expected_signature.clone();
            move |_, _| Ok(sig.clone())
        });

        let result = mock
            .sign(Some(generate_key(KeyAlgorithm::Ecdsa)), sample_message())
            .await;
        assert!(result.is_ok_and(|signature| signature == expected_signature));
    }

    #[tokio::test]
    async fn sign_should_return_error_if_invalid_byte_array() {
        let mut mock = MockClient::new();

        mock.expect_sign()
            .return_once(|_, _| Err(Report::new(AppError::InvalidByteArray.into())));

        let result = mock
            .sign(Some(generate_key(KeyAlgorithm::Ecdsa)), sample_message())
            .await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::App(AppError::InvalidByteArray)
        )));
    }

    #[tokio::test]
    async fn sign_should_return_error_if_internal_error_occurs() {
        let mut mock = MockClient::new();

        mock.expect_sign().return_once(|_, _| {
            Err(Report::new(
                GrpcError::InternalError("signing service unavailable".to_string()).into(),
            ))
        });

        let result = mock
            .sign(Some(generate_key(KeyAlgorithm::Ecdsa)), sample_message())
            .await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::Grpc(GrpcError::InternalError(_))
        )));
    }

    #[tokio::test]
    async fn sign_should_handle_none_key() {
        let mut mock = MockClient::new();

        mock.expect_sign()
            .return_once(|_, _| Ok(sample_signature()));

        let result = mock.sign(None, sample_message()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn key_should_succeed_returning_the_public_key() {
        let mut mock = MockClient::new();
        let expected_pub_key = sample_public_key();

        mock.expect_key().return_once({
            let key = expected_pub_key.clone();
            move |_| Ok(key.clone())
        });

        let result = mock.key(Some(generate_key(KeyAlgorithm::Ecdsa))).await;
        assert!(result.is_ok_and(|pub_key| pub_key == expected_pub_key));
    }

    #[tokio::test]
    async fn key_should_return_error_if_data_loss_occurs() {
        let mut mock = MockClient::new();

        mock.expect_key().return_once(|_| {
            Err(Report::new(
                GrpcError::DataLoss("connection lost during key retrieval".to_string()).into(),
            ))
        });

        let result = mock.key(Some(generate_key(KeyAlgorithm::Ecdsa))).await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::Grpc(GrpcError::DataLoss(_))
        )));
    }

    #[tokio::test]
    async fn key_should_handle_key_not_found() {
        let mut mock = MockClient::new();

        mock.expect_key().return_once(|_| {
            Err(Report::new(
                GrpcError::InvalidArgument("key not found".to_string()).into(),
            ))
        });

        let result = mock.key(Some(generate_key(KeyAlgorithm::Ecdsa))).await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::Grpc(GrpcError::InvalidArgument(_))
        )));
    }

    #[tokio::test]
    async fn subscribe_should_succeed_returning_the_stream() {
        let mut mock = MockClient::new();
        let events = block_begin_end_events(101);

        mock.expect_subscribe().return_once(move |_, _| {
            let result_events: Vec<error_stack::Result<Event, Error>> =
                events.clone().into_iter().map(Ok).collect();
            Ok(tokio_stream::iter(result_events))
        });

        let result = mock.subscribe(vec![], true).await;
        assert!(result.is_ok());

        let event_result_op = result.unwrap().next().await;
        assert!(event_result_op.is_some_and(|event_result| event_result.is_ok()));
    }

    #[tokio::test]
    async fn subscribe_should_return_error_if_data_loss_occurs() {
        let mut mock = MockClient::new();

        mock.expect_subscribe().return_once(|_, _| {
            Err(Report::new(
                GrpcError::DataLoss("client cannot keep up".to_string()).into(),
            ))
        });

        let result = mock.subscribe(vec![], true).await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::Grpc(GrpcError::DataLoss(_))
        )));
    }

    #[tokio::test]
    async fn subscribe_should_return_error_if_invalid_argument_is_provided() {
        let mut mock = MockClient::new();

        mock.expect_subscribe().return_once(|_, _| {
            Err(Report::new(
                GrpcError::InvalidArgument("Invalid filter provided".to_string()).into(),
            ))
        });

        let result = mock.subscribe(vec![], false).await;
        assert!(result.is_err_and(|error| matches!(
            error.current_context(),
            Error::Grpc(GrpcError::InvalidArgument(_))
        )));
    }

    #[test]
    fn keyid_from_key_algorithm_mapping() {
        let key_ecdsa = generate_key(KeyAlgorithm::Ecdsa);
        let key_ed25519 = generate_key(KeyAlgorithm::Ed25519);

        let keyid_ecdsa: KeyId = key_ecdsa.into();
        let keyid_ed25519: KeyId = key_ed25519.into();

        assert_eq!(keyid_ecdsa.algorithm, ampd_proto::Algorithm::Ecdsa as i32);
        assert_eq!(
            keyid_ed25519.algorithm,
            ampd_proto::Algorithm::Ed25519 as i32
        );
    }

    pub fn any_msg() -> Any {
        Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3, 4],
        }
    }

    pub fn contract_state_input_args() -> (nonempty::String, nonempty::Vec<u8>) {
        (
            nonempty::String::try_from("axelar1hg8mfs0pauxmxt5n76ndnlrye235zgz877l727".to_string())
                .unwrap(),
            nonempty::Vec::try_from(vec![1, 2, 3]).unwrap(),
        )
    }

    pub fn generate_key(algorithm: KeyAlgorithm) -> Key {
        Key {
            id: nonempty::String::try_from("test-key-1".to_string()).unwrap(),
            algorithm,
        }
    }

    pub fn block_begin_end_events(height: u64) -> Vec<Event> {
        vec![
            Event::BlockBegin(height.try_into().unwrap()),
            Event::BlockEnd(height.try_into().unwrap()),
        ]
    }

    pub fn sample_account_id() -> AccountId {
        AccountId::from_str("axelar1hg8mfs0pauxmxt5n76ndnlrye235zgz877l727").unwrap()
    }

    pub fn sample_contracts() -> ContractsAddresses {
        ContractsAddresses {
            voting_verifier: sample_account_id(),
            multisig_prover: sample_account_id(),
            service_registry: sample_account_id(),
            rewards: sample_account_id(),
        }
    }

    pub fn sample_broadcast_response() -> BroadcastClientResponse {
        BroadcastClientResponse {
            tx_hash: "ABCDEF1234567890".to_string(),
            index: 42,
        }
    }

    pub fn sample_signature() -> nonempty::Vec<u8> {
        nonempty::Vec::try_from(vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap()
    }

    pub fn sample_public_key() -> nonempty::Vec<u8> {
        nonempty::Vec::try_from(vec![0x04, 0x11, 0x22, 0x33, 0x44]).unwrap()
    }

    pub fn sample_message() -> nonempty::Vec<u8> {
        nonempty::Vec::try_from(b"hello world".to_vec()).unwrap()
    }
}

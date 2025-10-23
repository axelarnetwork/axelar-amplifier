use std::pin::Pin;

use ampd_proto;
use ampd_proto::blockchain_service_client::BlockchainServiceClient;
use ampd_proto::crypto_service_client::CryptoServiceClient;
use ampd_proto::{
    AddressRequest, BroadcastRequest, ContractStateRequest, ContractsRequest, KeyRequest,
    LatestBlockHeightRequest, SignRequest, SubscribeRequest,
};
use async_trait::async_trait;
use axelar_wasm_std::nonempty;
use cosmrs::AccountId;
use error_stack::{bail, Result, ResultExt as _};
use events::{AbciEventTypeFilter, Event};
use futures::StreamExt;
use report::{ResultCompatExt, ResultExt};
use serde::de::DeserializeOwned;
use tokio_stream::Stream;
use tonic::{transport, Code, Request, Status};

use crate::grpc::client::types::{BroadcastClientResponse, ChainName, ContractsAddresses, Key};

pub mod types;

pub(crate) fn parse_addr(addr: &str) -> Result<AccountId, Error> {
    addr.parse::<AccountId>()
        .change_context(AppError::InvalidAddress.into())
        .attach_printable(addr.to_string())
}
use crate::grpc::connection_pool::{ClientConnectionState, ConnectionHandle};
use crate::grpc::error::{AppError, Error};

fn is_transport_error(status: &Status) -> bool {
    match status.code() {
        Code::Unavailable => true,       // Service unavailable, connection issues
        Code::DeadlineExceeded => true,  // Timeout, connection hanging
        Code::ResourceExhausted => true, // Connection pool exhausted
        Code::Aborted => true,           // Connection aborted
        Code::Cancelled => true,         // Request cancelled, connection interrupted
        _ => false,
    }
}

#[async_trait]
pub trait EventHandlerClient {
    async fn contract_state<T: DeserializeOwned + 'static>(
        &mut self,
        contract: nonempty::String,
        query: nonempty::Vec<u8>,
    ) -> Result<T, Error>;

    async fn contracts(&mut self, chain: ChainName) -> Result<ContractsAddresses, Error>;

    async fn latest_block_height(&mut self) -> Result<u64, Error>;

    async fn sign(
        &mut self,
        key: Option<Key>,
        message: nonempty::Vec<u8>,
    ) -> Result<nonempty::Vec<u8>, Error>;

    async fn key(&mut self, key: Option<Key>) -> Result<nonempty::Vec<u8>, Error>;
}

#[async_trait]
pub trait HandlerTaskClient: EventHandlerClient {
    type Stream: Stream<Item = Result<Event, Error>>;

    async fn subscribe(
        &mut self,
        filters: Vec<AbciEventTypeFilter>,
        include_block_begin_end: bool,
    ) -> Result<Self::Stream, Error>;

    async fn address(&mut self) -> Result<AccountId, Error>;

    async fn broadcast(&mut self, msg: cosmrs::Any) -> Result<BroadcastClientResponse, Error>;
}

#[derive(Clone, Debug)]
pub struct GrpcClient {
    connection_handle: ConnectionHandle,
}

impl GrpcClient {
    pub fn new(connection_handle: ConnectionHandle) -> Self {
        Self { connection_handle }
    }

    async fn channel(&mut self) -> Result<transport::Channel, Error> {
        match self.connection_handle.connected_channel().await {
            Ok(ClientConnectionState::Connected(channel)) => Ok(channel),
            Ok(ClientConnectionState::Shutdown) => {
                Err(Error::from(AppError::PoolShutdown)).into_report()
            }
            Err(_) => Err(Error::from(AppError::ConnectionUnavailable)).into_report(),
        }
    }

    /// Called from inspect_err callbacks throughout gRPC client methods to trigger reconnection
    /// when transport/connection errors occur without blocking the main execution flow.
    ///
    /// Uses `tokio::spawn` because `inspect_err` requires a synchronous closure, but
    /// `request_reconnect()` is async. We want non-blocking fire-and-forget behavior.
    /// Alternative approaches (making callers async or using try_send) add more complexity.
    fn ensure_healthy_connection(&self, status: &Status) {
        if is_transport_error(status) {
            let handle = self.connection_handle.clone();
            tokio::spawn(async move {
                let _ = handle.request_reconnect().await;
            });
        }
    }
}

#[async_trait]
impl EventHandlerClient for GrpcClient {
    async fn contract_state<T: DeserializeOwned + 'static>(
        &mut self,
        contract: nonempty::String,
        query: nonempty::Vec<u8>,
    ) -> Result<T, Error> {
        let channel = self.channel().await?;
        let mut blockchain_client = BlockchainServiceClient::new(channel);

        blockchain_client
            .contract_state(ContractStateRequest {
                contract: contract.into(),
                query: query.into(),
            })
            .await
            .inspect_err(|status| self.ensure_healthy_connection(status))
            .into_report()
            .map(|response| response.into_inner().result)
            .and_then(|result| {
                serde_json::from_slice(&result)
                    .change_context(AppError::InvalidJson.into())
                    .attach_printable(hex::encode(&result))
            })
    }

    async fn contracts(&mut self, chain: ChainName) -> Result<ContractsAddresses, Error> {
        let channel = self.channel().await?;
        let mut blockchain_client = BlockchainServiceClient::new(channel);

        let contracts_response = blockchain_client
            .contracts(Request::new(ContractsRequest {
                chain: chain.into(),
            }))
            .await
            .inspect_err(|status| self.ensure_healthy_connection(status))
            .into_report()?
            .into_inner();

        ContractsAddresses::try_from(&contracts_response)
            .change_context(AppError::InvalidContractsResponse.into())
            .attach_printable(format!("{contracts_response:?}"))
    }

    async fn latest_block_height(&mut self) -> Result<u64, Error> {
        let channel = self.channel().await?;
        let mut blockchain_client = BlockchainServiceClient::new(channel);

        let height = blockchain_client
            .latest_block_height(Request::new(LatestBlockHeightRequest {}))
            .await
            .inspect_err(|status| self.ensure_healthy_connection(status))
            .into_report()?
            .into_inner()
            .height;

        Ok(height)
    }

    async fn sign(
        &mut self,
        key: Option<Key>,
        message: nonempty::Vec<u8>,
    ) -> Result<nonempty::Vec<u8>, Error> {
        let channel = self.channel().await?;
        let mut crypto_client = CryptoServiceClient::new(channel);

        crypto_client
            .sign(Request::new(SignRequest {
                key_id: key.map(|k| k.into()),
                msg: message.into(),
            }))
            .await
            .inspect_err(|status| self.ensure_healthy_connection(status))
            .into_report()
            .and_then(|response| {
                nonempty::Vec::try_from(response.into_inner().signature)
                    .change_context(AppError::InvalidByteArray.into())
            })
    }

    async fn key(&mut self, key: Option<Key>) -> Result<nonempty::Vec<u8>, Error> {
        let channel = self.channel().await?;
        let mut crypto_client = CryptoServiceClient::new(channel);

        crypto_client
            .key(Request::new(KeyRequest {
                key_id: key.map(|k| k.into()),
            }))
            .await
            .inspect_err(|status| self.ensure_healthy_connection(status))
            .into_report()
            .and_then(|response| {
                nonempty::Vec::try_from(response.into_inner().pub_key)
                    .change_context(AppError::InvalidByteArray.into())
            })
    }
}

#[async_trait]
impl HandlerTaskClient for GrpcClient {
    type Stream = Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>;

    async fn subscribe(
        &mut self,
        filters: Vec<AbciEventTypeFilter>,
        include_block_begin_end: bool,
    ) -> Result<Self::Stream, Error> {
        let channel = self.channel().await?;
        let mut blockchain_client = BlockchainServiceClient::new(channel);

        let request = SubscribeRequest {
            filters: filters
                .into_iter()
                .map(|filter| ampd_proto::EventFilter {
                    r#type: filter.event_type,
                    contract: filter.contract.to_string(),
                })
                .collect(),
            include_block_begin_end,
        };
        let streaming_response = blockchain_client
            .subscribe(request)
            .await
            .inspect_err(|status| self.ensure_healthy_connection(status))
            .into_report()?;

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
        let channel = self.channel().await?;
        let mut blockchain_client = BlockchainServiceClient::new(channel);

        let broadcaster_address = blockchain_client
            .address(Request::new(AddressRequest {}))
            .await
            .inspect_err(|status| self.ensure_healthy_connection(status))
            .into_report()?
            .into_inner()
            .address;

        let ampd_broadcaster_address = parse_addr(&broadcaster_address)?;
        Ok(ampd_broadcaster_address)
    }

    async fn broadcast(&mut self, msg: cosmrs::Any) -> Result<BroadcastClientResponse, Error> {
        let channel = self.channel().await?;
        let mut blockchain_client = BlockchainServiceClient::new(channel);
        let request = BroadcastRequest { msg: Some(msg) };

        let broadcast_response = blockchain_client
            .broadcast(request)
            .await
            .inspect_err(|status| self.ensure_healthy_connection(status))
            .into_report()?
            .into_inner();

        Ok(broadcast_response.into())
    }
}

#[cfg(test)]
pub mod tests {
    use std::str::FromStr;
    use std::vec;

    use ampd::url::Url;
    use ampd_proto::blockchain_service_server::{BlockchainService, BlockchainServiceServer};
    use ampd_proto::crypto_service_server::{CryptoService, CryptoServiceServer};
    use ampd_proto::{
        AddressResponse, BroadcastResponse, ContractStateResponse, ContractsResponse, KeyId,
        KeyResponse, LatestBlockHeightRequest, LatestBlockHeightResponse, SignResponse,
        SubscribeResponse,
    };
    use axelar_wasm_std::chain_name;
    use cosmrs::{AccountId, Any};
    use futures::StreamExt;
    use mockall::mock;

    mock! {
        #[derive(Debug)]
        pub HandlerTaskClient {}

        impl Clone for HandlerTaskClient {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl EventHandlerClient for HandlerTaskClient {
            async fn contract_state<T: DeserializeOwned + 'static>(
                &mut self,
                contract: nonempty::String,
                query: nonempty::Vec<u8>,
            ) -> Result<T, Error>;

            async fn contracts(&mut self, chain: ChainName) -> Result<ContractsAddresses, Error>;

            async fn latest_block_height(&mut self) -> Result<u64, Error>;

            async fn sign(
                &mut self,
                key: Option<Key>,
                message: nonempty::Vec<u8>,
            ) -> Result<nonempty::Vec<u8>, Error>;

            async fn key(&mut self, key: Option<Key>) -> Result<nonempty::Vec<u8>, Error>;
        }

        #[async_trait]
        impl HandlerTaskClient for HandlerTaskClient {
            type Stream = tokio_stream::Iter<vec::IntoIter<Result<Event, Error>>>;

            async fn subscribe(
                &mut self,
                filters: Vec<AbciEventTypeFilter>,
                include_block_begin_end: bool,
            ) -> Result<tokio_stream::Iter<vec::IntoIter<Result<Event, Error>>>, Error>;

            async fn address(&mut self) -> Result<AccountId, Error>;

            async fn broadcast(&mut self, msg: cosmrs::Any) -> Result<BroadcastClientResponse, Error>;
        }
    }

    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use tokio::time::{sleep, Duration};
    use tokio_util::sync::CancellationToken;
    use tonic::{Request, Response, Status};

    use super::*;
    use crate::grpc::client::types::KeyAlgorithm;
    use crate::grpc::connection_pool::{ConnectionPool, ConnectionState};
    use crate::grpc::error::GrpcError;

    type ServerSubscribeStream =
        Pin<Box<dyn Stream<Item = std::result::Result<SubscribeResponse, Status>> + Send>>;
    mock! {
        #[derive(Debug)]
        pub BlockchainService {}

        #[async_trait]
        impl BlockchainService for BlockchainService {
            type SubscribeStream = ServerSubscribeStream;
            async fn subscribe(&self, request: Request<SubscribeRequest>) -> std::result::Result<Response<ServerSubscribeStream>, Status>;
            async fn broadcast(&self, request: Request<BroadcastRequest>) -> std::result::Result<Response<BroadcastResponse>, Status>;
            async fn contract_state(&self, request: Request<ContractStateRequest>) -> std::result::Result<Response<ContractStateResponse>, Status>;
            async fn address(&self, request: Request<AddressRequest>) -> std::result::Result<Response<AddressResponse>, Status>;
            async fn contracts(&self, request: Request<ContractsRequest>) -> std::result::Result<Response<ContractsResponse>, Status>;
            async fn latest_block_height(&self, request: Request<LatestBlockHeightRequest>) -> std::result::Result<Response<LatestBlockHeightResponse>, Status>;
        }
    }

    mock! {
        #[derive(Debug)]
        pub CryptoService {}

        #[async_trait]
        impl CryptoService for CryptoService {
            async fn sign(&self, request: Request<SignRequest>) -> std::result::Result<Response<SignResponse>, Status>;
            async fn key(&self, request: Request<KeyRequest>) -> std::result::Result<Response<KeyResponse>, Status>;
        }
    }

    async fn test_setup(
        mock_blockchain: MockBlockchainService,
        mock_crypto: MockCryptoService,
    ) -> (GrpcClient, tokio::task::AbortHandle) {
        let server = transport::Server::builder()
            .add_service(BlockchainServiceServer::new(mock_blockchain))
            .add_service(CryptoServiceServer::new(mock_crypto));

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let bound_server =
            server.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener));

        tokio::spawn(bound_server);
        let pool_url = Url::new_sensitive(&format!("http://{}", server_addr)).unwrap();

        let (pool, connection_handle) = ConnectionPool::new(pool_url);
        let pool_task = tokio::spawn(async move { pool.run(CancellationToken::new()).await });
        let pool_abort_handle = pool_task.abort_handle();

        sleep(Duration::from_millis(100)).await;

        let client = GrpcClient::new(connection_handle);

        (client, pool_abort_handle)
    }

    #[tokio::test]
    async fn client_should_handle_connection_pool_reconnection() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_address = sample_account_id();
        let mock_response = AddressResponse {
            address: expected_address.to_string(),
        };

        mock_blockchain
            .expect_address()
            .times(2)
            .returning(move |_request| Ok(Response::new(mock_response.clone())));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let result = client.address().await;
        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());

        client.connection_handle.request_reconnect().await.unwrap();

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(matches!(
            client.connection_handle.connection_state(),
            ConnectionState::Connected(_)
        ));

        let second_result = client.address().await;
        assert!(
            second_result.is_ok(),
            "unexpected error: {}",
            second_result.unwrap_err()
        );
        assert_eq!(second_result.unwrap(), expected_address);
    }

    #[tokio::test]
    async fn address_should_succeed_returning_the_address() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_address = sample_account_id();
        let mock_response = AddressResponse {
            address: expected_address.to_string(),
        };

        mock_blockchain
            .expect_address()
            .return_once(move |_request| Ok(Response::new(mock_response)));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let result = client.address().await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_address);
    }

    #[tokio::test]
    async fn address_should_return_error_if_grpc_error_occurs() {
        let mut mock_blockchain = MockBlockchainService::new();

        mock_blockchain
            .expect_address()
            .return_once(|_request| Err(Status::unavailable("service unavailable")));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let result = client.address().await;

        assert!(result.is_err(), "unexpected Ok result: {}", result.unwrap());
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::Grpc(GrpcError::ServiceUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn address_should_return_error_if_invalid_argument_is_provided() {
        let mut mock_blockchain = MockBlockchainService::new();
        mock_blockchain
            .expect_address()
            .return_once(|_request| Err(Status::invalid_argument("invalid request")));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let result = client.address().await;

        assert!(
            result.is_err(),
            "unexpected Ok result: {:?}",
            result.unwrap()
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::Grpc(GrpcError::InvalidArgument(_))
        ));
    }

    #[tokio::test]
    async fn address_should_handle_multiple_consecutive_calls() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_address = sample_account_id();
        let mock_response = AddressResponse {
            address: expected_address.to_string(),
        };

        mock_blockchain
            .expect_address()
            .times(5)
            .returning(move |_request| Ok(Response::new(mock_response.clone())));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;

        for _ in 0..5 {
            let result = client.address().await;
            assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
            assert_eq!(result.unwrap(), expected_address);
        }
    }

    #[tokio::test]
    async fn latest_block_height_should_succeed_returning_the_height() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_height = 12345u64;
        let mock_response = LatestBlockHeightResponse {
            height: expected_height,
        };

        mock_blockchain
            .expect_latest_block_height()
            .return_once(move |_request| Ok(Response::new(mock_response)));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let result = client.latest_block_height().await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_height);
    }

    #[tokio::test]
    async fn latest_block_height_should_return_error_if_grpc_error_occurs() {
        let mut mock_blockchain = MockBlockchainService::new();

        mock_blockchain
            .expect_latest_block_height()
            .return_once(|_request| Err(Status::unavailable("service unavailable")));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let result = client.latest_block_height().await;

        assert!(result.is_err(), "unexpected Ok result: {}", result.unwrap());
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::Grpc(GrpcError::ServiceUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn broadcast_should_succeed_returning_the_response() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_response = sample_broadcast_response();
        let mock_response = BroadcastResponse {
            tx_hash: expected_response.tx_hash.clone(),
            index: expected_response.index,
        };

        mock_blockchain
            .expect_broadcast()
            .return_once(move |__request| Ok(Response::new(mock_response)));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let result = client.broadcast(any_msg()).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_response);
    }

    #[tokio::test]
    async fn broadcast_should_return_error_if_internal_error_occurs() {
        let mut mock_blockchain = MockBlockchainService::new();
        mock_blockchain
            .expect_broadcast()
            .return_once(|_request| Err(Status::internal("gas estimation failed")));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let result = client.broadcast(any_msg()).await;

        assert!(
            result.is_err(),
            "unexpected Ok result: {:?}",
            result.unwrap()
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::Grpc(GrpcError::InternalError(_))
        ));
    }

    #[tokio::test]
    async fn broadcast_should_handle_empty_message_value() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_response = sample_broadcast_response();
        let mock_response = BroadcastResponse {
            tx_hash: expected_response.tx_hash.clone(),
            index: expected_response.index,
        };

        mock_blockchain
            .expect_broadcast()
            .return_once(move |_request| Ok(Response::new(mock_response)));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;

        let empty_msg = Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![],
        };

        let result = client.broadcast(empty_msg).await;
        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
    }

    #[tokio::test]
    async fn contract_state_should_succeed_returning_the_response() {
        #[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
        struct TestResponse {
            balance: String,
            owner: String,
        }

        let mut mock_blockchain = MockBlockchainService::new();
        let expected_response = TestResponse {
            balance: "1000".to_string(),
            owner: "axelar1abc".to_string(),
        };
        let expected_response_clone = expected_response.clone();

        mock_blockchain
            .expect_contract_state()
            .return_once(move |_request| {
                Ok(Response::new(ContractStateResponse {
                    result: serde_json::to_vec(&expected_response_clone).unwrap(),
                }))
            });

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let (contract, query) = contract_state_input_args();
        let result: Result<TestResponse, Error> = client.contract_state(contract, query).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_response);
    }

    #[tokio::test]
    async fn contract_state_should_return_error_if_invalid_response() {
        let mut mock_blockchain = MockBlockchainService::new();

        mock_blockchain
            .expect_contract_state()
            .return_once(|_request| {
                Ok(Response::new(ContractStateResponse {
                    result: b"invalid json {".to_vec(),
                }))
            });

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let (contract, query) = contract_state_input_args();
        let result: Result<Value, Error> = client.contract_state(contract, query).await;

        assert!(
            result.is_err(),
            "unexpected Ok result: {:?}",
            result.unwrap()
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::App(AppError::InvalidJson)
        ));
    }

    #[tokio::test]
    async fn contract_state_should_return_error_if_operation_failed() {
        let mut mock_blockchain = MockBlockchainService::new();
        mock_blockchain
            .expect_contract_state()
            .return_once(|_request| Err(Status::unknown("contract execution failed")));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let (contract, query) = contract_state_input_args();
        let result: Result<Value, Error> = client.contract_state(contract, query).await;

        assert!(
            result.is_err(),
            "unexpected Ok result: {:?}",
            result.unwrap()
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::Grpc(GrpcError::OperationFailed(_))
        ));
    }

    #[tokio::test]
    async fn contracts_should_succeed_returning_the_response() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_contracts = sample_contracts();
        let mock_response = ContractsResponse {
            voting_verifier: expected_contracts.voting_verifier.to_string(),
            multisig_prover: expected_contracts.multisig_prover.to_string(),
            service_registry: expected_contracts.service_registry.to_string(),
            rewards: expected_contracts.rewards.to_string(),
            multisig: expected_contracts.multisig.to_string(),
        };

        mock_blockchain
            .expect_contracts()
            .return_once(move |_request| Ok(Response::new(mock_response)));

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let result = client.contracts(chain_name!("chain")).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_contracts);
    }

    #[tokio::test]
    async fn contracts_should_return_error_if_invalid_contracts_response() {
        let mut mock_blockchain = MockBlockchainService::new();
        mock_blockchain
            .expect_contracts()
            .return_once(move |_request| {
                Ok(Response::new(ContractsResponse {
                    voting_verifier: "".to_string(),
                    multisig_prover: "".to_string(),
                    service_registry: "".to_string(),
                    rewards: "".to_string(),
                    multisig: "".to_string(),
                }))
            });

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let result = client.contracts(chain_name!("chain")).await;

        assert!(
            result.is_err(),
            "unexpected Ok result: {:?}",
            result.unwrap()
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::App(AppError::InvalidContractsResponse)
        ));
    }

    #[tokio::test]
    async fn sign_should_succeed_returning_the_signature() {
        let mut mock_crypto = MockCryptoService::new();
        let expected_signature = sample_signature();
        let mock_response = SignResponse {
            signature: expected_signature.clone().into(),
        };

        mock_crypto
            .expect_sign()
            .return_once(|_request| Ok(Response::new(mock_response)));

        let (mut client, _) = test_setup(MockBlockchainService::new(), mock_crypto).await;
        let result = client
            .sign(Some(generate_key(KeyAlgorithm::Ecdsa)), sample_message())
            .await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_signature);
    }

    #[tokio::test]
    async fn sign_should_return_error_if_invalid_byte_array() {
        let mut mock_crypto = MockCryptoService::new();

        mock_crypto
            .expect_sign()
            .return_once(|_request| Ok(Response::new(SignResponse { signature: vec![] })));

        let (mut client, _) = test_setup(MockBlockchainService::new(), mock_crypto).await;
        let result = client
            .sign(Some(generate_key(KeyAlgorithm::Ecdsa)), sample_message())
            .await;

        assert!(
            result.is_err(),
            "unexpected Ok result: {:?}",
            result.unwrap()
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::App(AppError::InvalidByteArray)
        ));
    }

    #[tokio::test]
    async fn sign_should_return_error_if_internal_error_occurs() {
        let mut mock_crypto = MockCryptoService::new();

        mock_crypto
            .expect_sign()
            .return_once(|_request| Err(Status::internal("signing service unavailable")));

        let (mut client, _) = test_setup(MockBlockchainService::new(), mock_crypto).await;
        let result = client
            .sign(Some(generate_key(KeyAlgorithm::Ecdsa)), sample_message())
            .await;

        assert!(
            result.is_err(),
            "unexpected Ok result: {:?}",
            result.unwrap()
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::Grpc(GrpcError::InternalError(_))
        ));
    }

    #[tokio::test]
    async fn sign_should_handle_none_key() {
        let mut mock_crypto = MockCryptoService::new();
        let expected_signature = sample_signature();
        let mock_response = SignResponse {
            signature: expected_signature.clone().into(),
        };

        mock_crypto
            .expect_sign()
            .return_once(|_request| Ok(Response::new(mock_response)));

        let (mut client, _) = test_setup(MockBlockchainService::new(), mock_crypto).await;
        let result = client.sign(None, sample_message()).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_signature);
    }

    #[tokio::test]
    async fn key_should_succeed_returning_the_public_key() {
        let mut mock_crypto = MockCryptoService::new();
        let expected_public_key = sample_public_key();
        let mock_response = KeyResponse {
            pub_key: expected_public_key.clone().into(),
        };

        mock_crypto
            .expect_key()
            .return_once(|_request| Ok(Response::new(mock_response)));

        let (mut client, _) = test_setup(MockBlockchainService::new(), mock_crypto).await;
        let result = client.key(Some(generate_key(KeyAlgorithm::Ecdsa))).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_public_key);
    }

    #[tokio::test]
    async fn key_should_return_error_if_data_loss_occurs() {
        let mut mock_crypto = MockCryptoService::new();

        mock_crypto
            .expect_key()
            .return_once(|_request| Err(Status::data_loss("connection lost during key retrieval")));

        let (mut client, _) = test_setup(MockBlockchainService::new(), mock_crypto).await;
        let result = client.key(Some(generate_key(KeyAlgorithm::Ecdsa))).await;

        assert!(
            result.is_err(),
            "unexpected Ok result: {:?}",
            result.unwrap()
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::Grpc(GrpcError::DataLoss(_))
        ));
    }

    #[tokio::test]
    async fn key_should_handle_key_not_found() {
        let mut mock_crypto = MockCryptoService::new();

        mock_crypto
            .expect_key()
            .return_once(|_request| Err(Status::invalid_argument("key not found")));

        let (mut client, _) = test_setup(MockBlockchainService::new(), mock_crypto).await;
        let result = client.key(Some(generate_key(KeyAlgorithm::Ecdsa))).await;

        assert!(
            result.is_err(),
            "unexpected Ok result: {:?}",
            result.unwrap()
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::Grpc(GrpcError::InvalidArgument(_))
        ));
    }

    #[tokio::test]
    async fn subscribe_should_succeed_returning_the_stream() {
        let mut mock_blockchain = MockBlockchainService::new();
        let events = block_begin_end_events(101);

        mock_blockchain
            .expect_subscribe()
            .return_once(move |_request| {
                let subscribe_responses: Vec<SubscribeResponse> = events
                    .into_iter()
                    .map(|event| SubscribeResponse {
                        event: Some(event.into()),
                    })
                    .collect();

                Ok(Response::new(Box::pin(tokio_stream::iter(
                    subscribe_responses.into_iter().map(Ok),
                ))))
            });

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;
        let result = client.subscribe(vec![], true).await;
        assert!(result.is_ok());

        let event_result_op = result.unwrap().next().await;
        assert!(event_result_op.unwrap().is_ok());
    }

    #[tokio::test]
    async fn subscribe_should_return_error_if_data_loss_occurs() {
        let mut mock_blockchain = MockBlockchainService::new();

        mock_blockchain
            .expect_subscribe()
            .return_once(move |_request| {
                Ok(Response::new(Box::pin(tokio_stream::once(Err(
                    Status::data_loss("client cannot keep up"),
                )))))
            });

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;

        let result = client.subscribe(vec![], true).await;
        let next_steam_item = result.unwrap().next().await;
        assert!(next_steam_item.is_some());
        assert!(matches!(
            next_steam_item.unwrap().unwrap_err().current_context(),
            Error::Grpc(GrpcError::DataLoss(_))
        ));
    }

    #[tokio::test]
    async fn subscribe_should_return_error_if_invalid_argument_is_provided() {
        let mut mock_blockchain = MockBlockchainService::new();

        mock_blockchain
            .expect_subscribe()
            .return_once(move |_request| {
                Ok(Response::new(Box::pin(tokio_stream::once(Err(
                    Status::invalid_argument("invalid filter provided"),
                )))))
            });

        let (mut client, _) = test_setup(mock_blockchain, MockCryptoService::new()).await;

        let result = client.subscribe(vec![], true).await;
        let next_steam_item = result.unwrap().next().await;
        assert!(next_steam_item.is_some());
        assert!(matches!(
            next_steam_item.unwrap().unwrap_err().current_context(),
            Error::Grpc(GrpcError::InvalidArgument(_))
        ));
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
            multisig: sample_account_id(),
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

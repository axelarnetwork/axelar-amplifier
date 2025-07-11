use std::pin::Pin;
use std::vec;

use ampd::url::Url;
use ampd_proto;
use ampd_proto::blockchain_service_client::BlockchainServiceClient;
use ampd_proto::crypto_service_client::CryptoServiceClient;
use ampd_proto::{
    AddressRequest, BroadcastRequest, ContractStateRequest, ContractsRequest, KeyRequest,
    SignRequest, SubscribeRequest,
};
use async_trait::async_trait;
use axelar_wasm_std::nonempty;
use cosmrs::AccountId;
use error_stack::{bail, Result, ResultExt as _};
use events::{AbciEventTypeFilter, Event};
use futures::{Future, StreamExt};
use mockall::automock;
use report::ResultExt;
use serde::de::DeserializeOwned;
use tokio::time::Duration;
use tokio_stream::Stream;
use tonic::{transport, Request};
use tracing::{info, instrument, warn};

use crate::future::{with_retry_ctx, RetryPolicy};
use crate::grpc::error::{AppError, Error};
use crate::grpc::utils::{parse_addr, BroadcastClientResponse, ContractsAddresses, Key};

// TODO: make these configurable
const DEFAULT_INITIAL_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_RETRY_POLICY: RetryPolicy = RetryPolicy::RepeatConstant {
    sleep: Duration::from_secs(2),
    max_attempts: 3,
};
const KEEPALIVE_TIME: Duration = Duration::from_secs(30);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(3);
const KEEPALIVE_WHILE_IDLE: bool = true;

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
    pub url: Url,
}

#[instrument(skip(url))]
pub async fn new(url: &str) -> Result<GrpcClient, Error> {
    let endpoint: transport::Endpoint = url.parse().into_report()?;
    let endpoint = endpoint
        .connect_timeout(DEFAULT_INITIAL_TIMEOUT)
        .timeout(DEFAULT_RPC_TIMEOUT)
        .keep_alive_timeout(KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(KEEPALIVE_WHILE_IDLE)
        .http2_keep_alive_interval(KEEPALIVE_TIME);

    info!("connecting to ampd gRPC server");

    let conn = endpoint.connect().await.into_report()?;

    let blockchain = BlockchainServiceClient::new(conn.clone());
    let crypto = CryptoServiceClient::new(conn);

    info!("successfully connected to ampd gRPC server");

    Ok(GrpcClient {
        blockchain,
        crypto,
        url: Url::new_sensitive(url).change_context(AppError::InvalidUrl.into())?,
    })
}

impl GrpcClient {
    pub async fn reconnect(url: &Url) -> Result<Self, Error> {
        new(url.as_str()).await
    }

    fn should_reconnect(status: &tonic::Status) -> bool {
        matches!(
            status.code(),
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled
        )
    }

    #[allow(dead_code)]
    // This is a bugged implementation that doesn't work as expected.
    // It's left here for reference.
    async fn bugged_with_retry_and_reconnect<F, Fut, R>(&mut self, operation: F) -> Result<R, Error>
    where
        F: FnMut(&mut Self) -> Fut,
        Fut: Future<Output = std::result::Result<R, tonic::Status>>,
    {
        with_retry_ctx(
            self,
            operation,
            |client, op| {
                let fut = op(client);
                let url = client.url.clone();
                async move {
                    match tokio::time::timeout(DEFAULT_RPC_TIMEOUT, fut).await {
                        Ok(Ok(value)) => Ok(value),
                        Ok(Err(status)) => {
                            if Self::should_reconnect(&status) {
                                warn!(err = ?status, "connection to the ampd gRPC server was interrupted");
                                //The fundamental issue is that we can't mutate the original client from within
                                //the async closure due to lifetime constraints.
                                match Self::reconnect(&url).await {
                                    Ok(_) => {
                                        info!("successfully reconnected to ampd gRPC server");
                                    }
                                    Err(err) => {
                                        warn!(err = ?err, "reconnecting to the ampd gRPC server failed");
                                    }
                                }
                            }
                            Err(status).into_report()
                        }
                        Err(timeout_err) => {
                            warn!(err = ?timeout_err, "operation timed out");
                            Err(timeout_err).into_report()
                        }
                    }
                }
            },
            DEFAULT_RETRY_POLICY,
        )
        .await
    }

    async fn with_retry_and_reconnect<F, Fut, R>(
        &mut self,
        mut operation: F,
    ) -> Result<R, Error>
    where
        F: FnMut(&mut Self) -> Fut,
        Fut: Future<Output = std::result::Result<R, tonic::Status>>,
    {
        let max_attempts = DEFAULT_RETRY_POLICY.max_attempts();
        let mut attempts = 0u64;

        loop {
            attempts = attempts.saturating_add(1);

            match tokio::time::timeout(DEFAULT_RPC_TIMEOUT, operation(self)).await {
                Ok(Ok(value)) => return Ok(value),
                Ok(Err(status)) => {
                    if Self::should_reconnect(&status) {
                        warn!(err = ?status, "connection to the ampd gRPC server was interrupted");
                        match Self::reconnect(&self.url).await {
                            Ok(new_client) => {
                                *self = new_client;
                                info!("successfully reconnected to ampd gRPC server");
                            }
                            Err(err) => {
                                warn!(err = ?err, "reconnecting to the ampd gRPC server failed")
                            }
                        }
                    }

                    if attempts >= max_attempts {
                        return Err(status).into_report();
                    }

                    if let Some(delay) = DEFAULT_RETRY_POLICY.delay() {
                        tokio::time::sleep(delay).await;
                    }
                }
                Err(timeout_err) => {
                    warn!(err = ?timeout_err, "operation timed out");

                    if attempts >= max_attempts {
                        return Err(timeout_err).into_report();
                    }

                    tokio::time::sleep(DEFAULT_RPC_TIMEOUT).await;
                }
            }
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

        let streaming_response = self
            .with_retry_and_reconnect(|client| {
                let mut blockchain_client = client.blockchain.clone();
                let request = request.clone();
                async move { blockchain_client.subscribe(request).await }
            })
            .await?;

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
            .with_retry_and_reconnect(|client| {
                let mut blockchain_client = client.blockchain.clone();
                async move {
                    blockchain_client
                        .address(Request::new(AddressRequest {}))
                        .await
                }
            })
            .await?
            .into_inner()
            .address;

        let ampd_broadcaster_address = parse_addr(&broadcaster_address, "broadcaster")?;
        Ok(ampd_broadcaster_address)
    }

    async fn broadcast(&mut self, msg: cosmrs::Any) -> Result<BroadcastClientResponse, Error> {
        let broadcast_response = self
            .with_retry_and_reconnect(|client| {
                let mut blockchain_client = client.blockchain.clone();
                let request = BroadcastRequest {
                    msg: Some(msg.clone()),
                };
                async move { blockchain_client.broadcast(request).await }
            })
            .await?
            .into_inner();

        Ok(broadcast_response.into())
    }

    async fn contract_state<T: DeserializeOwned + 'static>(
        &mut self,
        contract: nonempty::String,
        query: nonempty::Vec<u8>,
    ) -> Result<T, Error> {
        let request = ContractStateRequest {
            contract: contract.into(),
            query: query.into(),
        };

        self.with_retry_and_reconnect(|client| {
            let mut blockchain_client = client.blockchain.clone();
            let request = request.clone();
            async move { blockchain_client.contract_state(request).await }
        })
        .await
        .map(|response| response.into_inner().result)
        .and_then(|result| {
            serde_json::from_slice(&result)
                .change_context(AppError::InvalidJson.into())
                .attach_printable(hex::encode(&result))
        })
    }

    async fn contracts(&mut self) -> Result<ContractsAddresses, Error> {
        let response = self
            .with_retry_and_reconnect(|client| {
                let mut blockchain_client = client.blockchain.clone();
                async move {
                    blockchain_client
                        .contracts(Request::new(ContractsRequest {}))
                        .await
                }
            })
            .await?
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
        let request = SignRequest {
            key_id: key.map(|k| k.into()),
            msg: message.into(),
        };

        self.with_retry_and_reconnect(|client| {
            let mut crypto_client = client.crypto.clone();
            let request = request.clone();
            async move { crypto_client.sign(request).await }
        })
        .await
        .and_then(|response| {
            nonempty::Vec::try_from(response.into_inner().signature)
                .change_context(AppError::InvalidByteArray.into())
        })
    }

    async fn key(&mut self, key: Option<Key>) -> Result<nonempty::Vec<u8>, Error> {
        let request = KeyRequest {
            key_id: key.map(|k| k.into()),
        };

        self.with_retry_and_reconnect(|client| {
            let mut crypto_client = client.crypto.clone();
            let request = request.clone();
            async move { crypto_client.key(request).await }
        })
        .await
        .and_then(|response| {
            nonempty::Vec::try_from(response.into_inner().pub_key)
                .change_context(AppError::InvalidByteArray.into())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use ampd_proto::blockchain_service_server::{BlockchainService, BlockchainServiceServer};
    use ampd_proto::crypto_service_server::{CryptoService, CryptoServiceServer};
    use ampd_proto::{
        AddressResponse, BroadcastResponse, ContractStateResponse, ContractsResponse, KeyId,
        KeyResponse, SignResponse, SubscribeResponse,
    };
    use cosmrs::{AccountId, Any};
    use futures::StreamExt;
    use mockall::mock;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use tonic::{Request, Response, Status};

    use super::*;
    use crate::grpc::client::new as new_client;
    use crate::grpc::error::GrpcError;
    use crate::grpc::utils::KeyAlgorithm;

    #[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
    pub struct TestContractStateResponse {
        balance: String,
        owner: String,
    }

    type ServerSubscribeStream =
        Pin<Box<dyn Stream<Item = std::result::Result<SubscribeResponse, Status>> + Send>>;
    mock! {
        #[derive(Debug)]
        pub BlockchainService {}

        #[async_trait]
        impl BlockchainService for BlockchainService {
            type SubscribeStream = ServerSubscribeStream;
            async fn address(&self, request: Request<AddressRequest>) -> std::result::Result<Response<AddressResponse>, Status>;
            async fn broadcast(&self, request: Request<BroadcastRequest>) -> std::result::Result<Response<BroadcastResponse>, Status>;
            async fn contract_state(&self, request: Request<ContractStateRequest>) -> std::result::Result<Response<ContractStateResponse>, Status>;
            async fn contracts(&self, request: Request<ContractsRequest>) -> std::result::Result<Response<ContractsResponse>, Status>;
            async fn subscribe(&self, request: Request<SubscribeRequest>) -> std::result::Result<Response<ServerSubscribeStream>, Status>;
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

    async fn setup_test_client(
        mock_blockchain: MockBlockchainService,
        mock_crypto: MockCryptoService,
    ) -> (GrpcClient, tokio::task::AbortHandle, std::net::SocketAddr) {
        let server = tonic::transport::Server::builder()
            .add_service(BlockchainServiceServer::new(mock_blockchain))
            .add_service(CryptoServiceServer::new(mock_crypto));

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let bound_server =
            server.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener));

        let server_handle = tokio::spawn(bound_server);
        let abort_handle = server_handle.abort_handle();

        let url = format!("http://{}", server_addr);
        let client = new_client(&url).await.unwrap();

        (client, abort_handle, server_addr)
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

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
        let result = client.address().await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_address);
    }

    #[tokio::test]
    async fn address_should_return_error_if_grpc_error_occurs() {
        let mut mock_blockchain = MockBlockchainService::new();
        mock_blockchain
            .expect_address()
            .returning(|_request| Err(Status::unavailable("service unavailable")));

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
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
            .returning(|_request| Err(Status::invalid_argument("invalid request")));

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
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

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;

        for _ in 0..5 {
            let result = client.address().await;
            assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
            assert_eq!(result.unwrap(), expected_address);
        }
    }

    #[tokio::test]
    async fn address_should_retry_on_transient_failures() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_address = sample_account_id();
        let mock_response = AddressResponse {
            address: expected_address.to_string(),
        };
        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        mock_blockchain
            .expect_address()
            .times(3)
            .returning(move |_request| {
                let mut count = call_count_clone.lock().unwrap();
                *count += 1;

                if *count <= 2 {
                    Err(Status::unavailable("service temporarily unavailable"))
                } else {
                    Ok(Response::new(mock_response.clone()))
                }
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;

        let start_time = Instant::now();
        let result = client.address().await;
        let elapsed = start_time.elapsed();

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_address);

        assert!(elapsed >= Duration::from_secs(4));
        assert_eq!(*call_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn address_should_fail_after_max_retries() {
        let mut mock_blockchain = MockBlockchainService::new();
        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        mock_blockchain
            .expect_address()
            .times(3)
            .returning(move |_request| {
                let mut count = call_count_clone.lock().unwrap();
                *count += 1;

                Err(Status::unavailable("persistent service failure"))
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;

        let start_time = Instant::now();
        let result = client.address().await;
        let elapsed = start_time.elapsed();

        assert!(
            result.is_err(),
            "unexpected Ok result: {:?}",
            result.unwrap()
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::Grpc(GrpcError::ServiceUnavailable(_))
        ));

        assert!(elapsed >= Duration::from_secs(4));
        assert!(elapsed < Duration::from_secs(5));
        assert_eq!(*call_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn address_should_reconnect_after_server_restart() {
        let expected_address = sample_account_id();
        let expected_address_clone = expected_address.clone();
        let mock_response = AddressResponse {
            address: expected_address.to_string(),
        };

        let mut mock_blockchain = MockBlockchainService::new();
        mock_blockchain
            .expect_address()
            .times(1)
            .returning(move |_request| Ok(Response::new(mock_response.clone())));

        mock_blockchain
            .expect_address()
            .times(3)
            .returning(|_request| Err(Status::unavailable("server is down")));

        let (mut client, server_abort_handle, server_addr) =
            setup_test_client(mock_blockchain, MockCryptoService::new()).await;

        let result = client.address().await;
        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());

        server_abort_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let result = client.address().await;
        assert!(result.is_err(), "unexpected Ok result: {}", result.unwrap());

        let mut new_mock = MockBlockchainService::new();
        new_mock
            .expect_address()
            .times(1)
            .returning(move |_request| {
                Ok(Response::new(AddressResponse {
                    address: expected_address_clone.to_string(),
                }))
            });

        let _new_server_handle =
            restart_server_on_addr(server_addr, new_mock, MockCryptoService::new()).await;

        let mut new_client = GrpcClient::reconnect(&client.url).await.unwrap();

        let result = new_client.address().await;
        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_address);
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

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
        let result = client.broadcast(any_msg()).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_response);
    }

    #[tokio::test]
    async fn broadcast_should_return_error_if_internal_error_occurs() {
        let mut mock_blockchain = MockBlockchainService::new();
        mock_blockchain
            .expect_broadcast()
            .returning(|_request| Err(Status::internal("gas estimation failed")));

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
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

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;

        let empty_msg = Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![],
        };

        let result = client.broadcast(empty_msg).await;
        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
    }

    #[tokio::test]
    async fn broadcast_should_retry_on_network_errors() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_response = sample_broadcast_response();
        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        mock_blockchain
            .expect_broadcast()
            .times(2)
            .returning(move |_request| {
                let mut count = call_count_clone.lock().unwrap();
                *count += 1;

                if *count == 1 {
                    Err(Status::unavailable("network error"))
                } else {
                    Ok(Response::new(BroadcastResponse {
                        tx_hash: sample_broadcast_response().tx_hash,
                        index: sample_broadcast_response().index,
                    }))
                }
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
        let result = client.broadcast(any_msg()).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_response);
        assert_eq!(*call_count.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn contract_state_should_succeed_returning_the_response() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_response = sample_contract_state_response();
        let expected_response_clone = expected_response.clone();

        mock_blockchain
            .expect_contract_state()
            .return_once(move |_request| {
                Ok(Response::new(ContractStateResponse {
                    result: serde_json::to_vec(&expected_response_clone).unwrap(),
                }))
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
        let (contract, query) = contract_state_input_args();
        let result: Result<TestContractStateResponse, Error> =
            client.contract_state(contract, query).await;

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

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
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
            .returning(|_request| Err(Status::unknown("contract execution failed")));

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
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
    async fn contract_state_should_retry_on_temporary_failures() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_response = sample_contract_state_response();
        let expected_response_clone = expected_response.clone();
        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        mock_blockchain
            .expect_contract_state()
            .times(2)
            .returning(move |_request| {
                let mut count = call_count_clone.lock().unwrap();
                *count += 1;

                if *count == 1 {
                    Err(Status::deadline_exceeded("request timeout"))
                } else {
                    Ok(Response::new(ContractStateResponse {
                        result: serde_json::to_vec(&expected_response_clone).unwrap(),
                    }))
                }
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
        let (contract, query) = contract_state_input_args();
        let result: Result<TestContractStateResponse, Error> =
            client.contract_state(contract, query).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_response);
        assert_eq!(*call_count.lock().unwrap(), 2);
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
        };

        mock_blockchain
            .expect_contracts()
            .return_once(move |_request| Ok(Response::new(mock_response)));

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
        let result = client.contracts().await;

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
                }))
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;

        let result = client.contracts().await;

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
    async fn contracts_should_retry_on_server_errors() {
        let mut mock_blockchain = MockBlockchainService::new();
        let expected_contracts = sample_contracts();
        let mock_response = ContractsResponse {
            voting_verifier: expected_contracts.voting_verifier.to_string(),
            multisig_prover: expected_contracts.multisig_prover.to_string(),
            service_registry: expected_contracts.service_registry.to_string(),
            rewards: expected_contracts.rewards.to_string(),
        };
        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        mock_blockchain
            .expect_contracts()
            .times(3)
            .returning(move |_request| {
                let mut count = call_count_clone.lock().unwrap();
                *count += 1;

                if *count <= 2 {
                    Err(Status::internal("server overloaded"))
                } else {
                    Ok(Response::new(mock_response.clone()))
                }
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
        let result = client.contracts().await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_contracts);
        assert_eq!(*call_count.lock().unwrap(), 3);
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

        let (mut client, _, _) = setup_test_client(MockBlockchainService::new(), mock_crypto).await;
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

        let (mut client, _, _) = setup_test_client(MockBlockchainService::new(), mock_crypto).await;

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
            .returning(|_request| Err(Status::internal("signing service unavailable")));

        let (mut client, _, _) = setup_test_client(MockBlockchainService::new(), mock_crypto).await;

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

        let (mut client, _, _) = setup_test_client(MockBlockchainService::new(), mock_crypto).await;
        let result = client.sign(None, sample_message()).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_signature);
    }

    #[tokio::test]
    async fn sign_should_retry_on_crypto_service_failures() {
        let mut mock_crypto = MockCryptoService::new();
        let expected_signature = sample_signature();
        let mock_response = SignResponse {
            signature: expected_signature.clone().into(),
        };
        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        mock_crypto
            .expect_sign()
            .times(2)
            .returning(move |_request| {
                let mut count = call_count_clone.lock().unwrap();
                *count += 1;

                if *count == 1 {
                    Err(Status::resource_exhausted("crypto service busy"))
                } else {
                    Ok(Response::new(mock_response.clone()))
                }
            });

        let (mut client, _, _) = setup_test_client(MockBlockchainService::new(), mock_crypto).await;
        let result = client
            .sign(Some(generate_key(KeyAlgorithm::Ecdsa)), sample_message())
            .await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_signature);
        assert_eq!(*call_count.lock().unwrap(), 2);
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

        let (mut client, _, _) = setup_test_client(MockBlockchainService::new(), mock_crypto).await;
        let result = client.key(Some(generate_key(KeyAlgorithm::Ecdsa))).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_public_key);
    }

    #[tokio::test]
    async fn key_should_return_error_if_data_loss_occurs() {
        let mut mock_crypto = MockCryptoService::new();

        mock_crypto
            .expect_key()
            .returning(|_request| Err(Status::data_loss("connection lost during key retrieval")));

        let (mut client, _, _) = setup_test_client(MockBlockchainService::new(), mock_crypto).await;

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
            .returning(|_request| Err(Status::invalid_argument("key not found")));

        let (mut client, _, _) = setup_test_client(MockBlockchainService::new(), mock_crypto).await;

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
    async fn key_should_retry_on_transient_crypto_errors() {
        let mut mock_crypto = MockCryptoService::new();
        let expected_public_key = sample_public_key();
        let mock_response = KeyResponse {
            pub_key: expected_public_key.clone().into(),
        };
        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        mock_crypto
            .expect_key()
            .times(3)
            .returning(move |_request| {
                let mut count = call_count_clone.lock().unwrap();
                *count += 1;

                if *count <= 2 {
                    Err(Status::unavailable("key service temporarily down"))
                } else {
                    Ok(Response::new(mock_response.clone()))
                }
            });

        let (mut client, _, _) = setup_test_client(MockBlockchainService::new(), mock_crypto).await;
        let result = client.key(Some(generate_key(KeyAlgorithm::Ecdsa))).await;

        assert!(result.is_ok(), "unexpected error: {}", result.unwrap_err());
        assert_eq!(result.unwrap(), expected_public_key);
        assert_eq!(*call_count.lock().unwrap(), 3);
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
                    subscribe_responses.into_iter().map(std::result::Result::Ok),
                ))))
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
        let result = client.subscribe(vec![], true).await;
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());

        let event_result_op = result.unwrap().next().await;
        assert!(event_result_op.unwrap().is_ok());
    }

    #[tokio::test]
    async fn subscribe_should_return_error_if_data_loss_occurs() {
        let mut mock_blockchain = MockBlockchainService::new();

        mock_blockchain
            .expect_subscribe()
            .return_once(move |_request| {
                Ok(Response::new(Box::pin(tokio_stream::once(
                    std::result::Result::Err(Status::data_loss("client cannot keep up")),
                ))))
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;

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
                Ok(Response::new(Box::pin(tokio_stream::once(
                    std::result::Result::Err(Status::invalid_argument("invalid filter provided")),
                ))))
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;

        let result = client.subscribe(vec![], true).await;
        let next_steam_item = result.unwrap().next().await;
        assert!(next_steam_item.is_some());
        assert!(matches!(
            next_steam_item.unwrap().unwrap_err().current_context(),
            Error::Grpc(GrpcError::InvalidArgument(_))
        ));
    }

    #[tokio::test]
    async fn subscribe_should_retry_on_connection_failures() {
        let mut mock_blockchain = MockBlockchainService::new();
        let call_count = Arc::new(Mutex::new(0));
        let call_count_clone = call_count.clone();

        mock_blockchain
            .expect_subscribe()
            .times(2)
            .returning(move |_request| {
                let mut count = call_count_clone.lock().unwrap();
                *count += 1;

                if *count == 1 {
                    Err(Status::unavailable("connection lost"))
                } else {
                    let subscribe_responses: Vec<SubscribeResponse> = block_begin_end_events(101)
                        .into_iter()
                        .map(|event| SubscribeResponse {
                            event: Some(event.into()),
                        })
                        .collect();

                    Ok(Response::new(Box::pin(tokio_stream::iter(
                        subscribe_responses.into_iter().map(std::result::Result::Ok),
                    ))))
                }
            });

        let (mut client, _, _) = setup_test_client(mock_blockchain, MockCryptoService::new()).await;
        let result = client.subscribe(vec![], true).await;

        assert!(result.is_ok(), "unexpected error: {:?}", result.err());
        assert_eq!(*call_count.lock().unwrap(), 2);

        let event_result_op = result.unwrap().next().await;
        assert!(event_result_op.unwrap().is_ok());
    }

    #[tokio::test]
    async fn subscribe_should_reconnect_after_server_restart() {
        let test_events = block_begin_end_events(101);
        let test_events_clone = test_events.clone();

        let mut initial_mock_blockchain = MockBlockchainService::new();

        initial_mock_blockchain
            .expect_subscribe()
            .times(1)
            .returning(move |_request| {
                let subscribe_responses: Vec<SubscribeResponse> = test_events
                    .clone()
                    .into_iter()
                    .map(|event| SubscribeResponse {
                        event: Some(event.into()),
                    })
                    .collect();

                Ok(Response::new(Box::pin(tokio_stream::iter(
                    subscribe_responses.into_iter().map(std::result::Result::Ok),
                ))))
            });

        initial_mock_blockchain
            .expect_subscribe()
            .times(3)
            .returning(|_request| Err(Status::unavailable("server is down")));

        let (mut client, server_abort_handle, server_addr) =
            setup_test_client(initial_mock_blockchain, MockCryptoService::new()).await;

        let mut stream = client.subscribe(vec![], true).await.unwrap();

        let first_event = stream.next().await;
        assert!(first_event.is_some(), "Should receive first event");
        let block_begin_event = first_event.unwrap().unwrap();
        assert_eq!(
            block_begin_event,
            Event::BlockBegin(101u64.try_into().unwrap())
        );

        server_abort_handle.abort();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let start_time = std::time::Instant::now();
        let result = client.subscribe(vec![], true).await;
        let elapsed = start_time.elapsed();

        assert!(result.is_err());
        assert!(elapsed >= Duration::from_secs(4));

        let mut restart_mock_blockchain = MockBlockchainService::new();
        restart_mock_blockchain
            .expect_subscribe()
            .times(1)
            .returning(move |_request| {
                let subscribe_responses: Vec<SubscribeResponse> = test_events_clone
                    .clone()
                    .into_iter()
                    .map(|event| SubscribeResponse {
                        event: Some(event.into()),
                    })
                    .collect();

                Ok(Response::new(Box::pin(tokio_stream::iter(
                    subscribe_responses.into_iter().map(std::result::Result::Ok),
                ))))
            });

        let _new_server_handle = restart_server_on_addr(
            server_addr,
            restart_mock_blockchain,
            MockCryptoService::new(),
        )
        .await;

        let mut new_client = GrpcClient::reconnect(&client.url).await.unwrap();

        let result = new_client.subscribe(vec![], true).await;
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());

        let mut new_stream = result.unwrap();
        let reconnected_event = new_stream.next().await;
        assert!(reconnected_event.is_some());

        let event_result = reconnected_event.unwrap();
        assert!(event_result.is_ok());

        let event = event_result.unwrap();
        assert_eq!(event, Event::BlockBegin(101u64.try_into().unwrap()));
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

    pub fn sample_contract_state_response() -> TestContractStateResponse {
        TestContractStateResponse {
            balance: "1000".to_string(),
            owner: "axelar1abc".to_string(),
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

    async fn restart_server_on_addr(
        addr: std::net::SocketAddr,
        mock_blockchain: MockBlockchainService,
        mock_crypto: MockCryptoService,
    ) -> tokio::task::AbortHandle {
        let server = tonic::transport::Server::builder()
            .add_service(BlockchainServiceServer::new(mock_blockchain))
            .add_service(CryptoServiceServer::new(mock_crypto));

        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let bound_server =
            server.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener));

        let server_handle = tokio::spawn(bound_server);
        server_handle.abort_handle()
    }
}

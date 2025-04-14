use async_trait::async_trait;
use cosmrs::proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmrs::proto::cosmos::auth::v1beta1::{
    BaseAccount, QueryAccountRequest, QueryAccountResponse,
};
use cosmrs::proto::cosmos::bank::v1beta1::query_client::QueryClient as BankQueryClient;
use cosmrs::proto::cosmos::bank::v1beta1::{QueryBalanceRequest, QueryBalanceResponse};
use cosmrs::proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmrs::proto::cosmos::tx::v1beta1::{
    BroadcastTxRequest, BroadcastTxResponse, GetTxRequest, GetTxResponse, SimulateRequest,
    SimulateResponse,
};
use cosmrs::tx::MessageExt;
use cosmrs::Any;
use error_stack::{report, ResultExt};
use mockall::mock;
use prost::Message;
use report::ErrorExt;
use thiserror::Error;
use tonic::transport::Channel;
use tonic::Response;

use crate::broadcaster::tx::Tx;
use crate::types::{CosmosPublicKey, TMAddress};

type Result<T> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),
    #[error("failed to make the grpc request")]
    GrpcRequest(#[from] tonic::Status),
    #[error("failed building tx")]
    TxBuilding,
    #[error("gas info is missing in the query response")]
    GasInfoMissing,
    #[error("account is missing in the query response")]
    AccountMissing,
    #[error("failed to decode the query response")]
    MalformedResponse,
}

mock! {
    #[derive(Debug)]
    pub CosmosClient{}

    impl Clone for CosmosClient {
        fn clone(&self) -> Self;
    }


    #[async_trait]
    impl CosmosClient for CosmosClient {
        async fn broadcast_tx(&mut self, req: BroadcastTxRequest) -> Result<BroadcastTxResponse>;
        async fn simulate(&mut self, req: SimulateRequest) -> Result<SimulateResponse>;
        async fn tx(&mut self, req: GetTxRequest) -> Result<GetTxResponse>;

        async fn account(&mut self, address: QueryAccountRequest) -> Result<QueryAccountResponse>;

        async fn balance(&mut self, request: QueryBalanceRequest) -> Result<QueryBalanceResponse>;
    }
}

#[async_trait]
pub trait CosmosClient {
    async fn broadcast_tx(&mut self, req: BroadcastTxRequest) -> Result<BroadcastTxResponse>;
    async fn simulate(&mut self, req: SimulateRequest) -> Result<SimulateResponse>;
    async fn tx(&mut self, req: GetTxRequest) -> Result<GetTxResponse>;

    async fn account(&mut self, address: QueryAccountRequest) -> Result<QueryAccountResponse>;

    async fn balance(&mut self, request: QueryBalanceRequest) -> Result<QueryBalanceResponse>;
}

/// CosmosGrpcClient implements the CosmosClient trait to interact with Cosmos blockchain nodes via gRPC.
///
/// # Clone Implementation
///
/// This struct derives the `Clone` trait, which enables creating copies of the client instance.
/// When `clone()` is called on a CosmosGrpcClient:
///
/// - A new CosmosGrpcClient instance is created with cloned fields
/// - The underlying gRPC clients (auth, bank, service) are cloned
/// - The tonic::transport::Channel is cloned, but this doesn't create a new TCP connection
///   Instead, it creates a new reference to the same underlying connection pool
///
/// This cloning approach is efficient for concurrent operations since it allows multiple
/// client instances to share the same connection resources while maintaining independent state.
///
#[derive(Clone)]
pub struct CosmosGrpcClient {
    auth: AuthQueryClient<Channel>,
    bank: BankQueryClient<Channel>,
    service: ServiceClient<Channel>,
}

impl CosmosGrpcClient {
    pub async fn new(url: &str) -> Result<Self> {
        let endpoint: tonic::transport::Endpoint = url.parse().map_err(ErrorExt::into_report)?;
        let conn = endpoint.connect().await.map_err(ErrorExt::into_report)?;

        Ok(Self {
            auth: AuthQueryClient::new(conn.clone()),
            bank: BankQueryClient::new(conn.clone()),
            service: ServiceClient::new(conn),
        })
    }
}

#[async_trait]
impl CosmosClient for CosmosGrpcClient {
    async fn broadcast_tx(&mut self, request: BroadcastTxRequest) -> Result<BroadcastTxResponse> {
        self.service
            .broadcast_tx(request)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }

    async fn simulate(&mut self, req: SimulateRequest) -> Result<SimulateResponse> {
        self.service
            .simulate(req)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }

    async fn tx(&mut self, req: GetTxRequest) -> Result<GetTxResponse> {
        self.service
            .get_tx(req)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }

    async fn account(&mut self, request: QueryAccountRequest) -> Result<QueryAccountResponse> {
        self.auth
            .account(request)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }

    async fn balance(&mut self, request: QueryBalanceRequest) -> Result<QueryBalanceResponse> {
        self.bank
            .balance(request)
            .await
            .map(Response::into_inner)
            .map_err(ErrorExt::into_report)
    }
}

pub async fn estimate_gas<T>(
    client: &mut T,
    msgs: Vec<Any>,
    pub_key: CosmosPublicKey,
    acc_sequence: u64,
) -> Result<u64>
where
    T: CosmosClient,
{
    let tx_bytes = Tx::builder()
        .msgs(msgs)
        .pub_key(pub_key)
        .acc_sequence(acc_sequence)
        .build()
        .with_dummy_sig()
        .await
        .expect("dummy signature must be valid")
        .to_bytes()
        .change_context(Error::TxBuilding)?;

    #[allow(deprecated)]
    client
        .simulate(SimulateRequest { tx: None, tx_bytes })
        .await
        .and_then(|res| {
            res.gas_info
                .map(|info| info.gas_used)
                .ok_or(report!(Error::GasInfoMissing))
        })
}

pub async fn account<T>(client: &mut T, address: &TMAddress) -> Result<BaseAccount>
where
    T: CosmosClient,
{
    client
        .account(QueryAccountRequest {
            address: address.to_string(),
        })
        .await
        .and_then(|res| res.account.ok_or(report!(Error::AccountMissing)))
        .and_then(decode_base_account)
}

fn decode_base_account(account: Any) -> Result<BaseAccount> {
    BaseAccount::decode(&account.value[..]).change_context(Error::MalformedResponse)
}

#[cfg(test)]
mod tests {
    use axelar_wasm_std::assert_err_contains;
    use mockall::predicate;

    use super::*;
    use crate::types::random_cosmos_public_key;
    use crate::PREFIX;

    #[tokio::test]
    async fn estimate_gas_success() {
        let pub_key = random_cosmos_public_key();
        let acc_sequence = 5u64;
        let msgs = vec![Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3],
        }];
        let gas_used = 150000u64;

        let mut mock_client = MockCosmosClient::new();
        mock_client.expect_simulate().return_once(move |_| {
            Ok(SimulateResponse {
                gas_info: Some(cosmrs::proto::cosmos::base::abci::v1beta1::GasInfo {
                    gas_wanted: 200000,
                    gas_used,
                }),
                result: None,
            })
        });

        let actual = estimate_gas(&mut mock_client, msgs, pub_key, acc_sequence).await;

        assert_eq!(actual.unwrap(), gas_used);
    }

    #[tokio::test]
    async fn estimate_gas_missing_gas_info() {
        let pub_key = random_cosmos_public_key();
        let acc_sequence = 5u64;
        let msgs = vec![Any {
            type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
            value: vec![1, 2, 3],
        }];

        let mut mock_client = MockCosmosClient::new();
        mock_client.expect_simulate().return_once(|_| {
            Ok(SimulateResponse {
                gas_info: None,
                result: None,
            })
        });

        let actual = estimate_gas(&mut mock_client, msgs, pub_key, acc_sequence).await;

        assert_err_contains!(actual, Error, Error::GasInfoMissing);
    }

    #[tokio::test]
    async fn account_success() {
        let address = TMAddress::random(PREFIX);
        let base_account = BaseAccount {
            address: address.to_string(),
            pub_key: None,
            account_number: 42,
            sequence: 10,
        };
        let base_account_any = base_account.to_any().unwrap();

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(base_account_any),
                })
            });

        let actual = account(&mut mock_client, &address).await;

        assert_eq!(actual.unwrap(), base_account);
    }

    #[tokio::test]
    async fn account_account_missing() {
        let address = TMAddress::random(PREFIX);

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .return_once(move |_| Ok(QueryAccountResponse { account: None }));

        let actual = account(&mut mock_client, &address).await;

        assert_err_contains!(actual, Error, Error::AccountMissing);
    }

    #[tokio::test]
    async fn account_malformed_response() {
        let address = TMAddress::random(PREFIX);

        let mut mock_client = MockCosmosClient::new();
        mock_client
            .expect_account()
            .with(predicate::eq(QueryAccountRequest {
                address: address.to_string(),
            }))
            .return_once(move |_| {
                Ok(QueryAccountResponse {
                    account: Some(Any {
                        type_url: "/cosmos.bank.v1beta1.MsgSend".to_string(),
                        value: vec![1, 2, 3],
                    }),
                })
            });

        let actual = account(&mut mock_client, &address).await;

        assert_err_contains!(actual, Error, Error::MalformedResponse);
    }
}

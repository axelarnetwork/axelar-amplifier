use async_trait::async_trait;
use cosmrs::proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmrs::proto::cosmos::auth::v1beta1::{QueryAccountRequest, QueryAccountResponse};
use cosmrs::proto::cosmos::bank::v1beta1::query_client::QueryClient as BankQueryClient;
use cosmrs::proto::cosmos::bank::v1beta1::{QueryBalanceRequest, QueryBalanceResponse};
use cosmrs::proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmrs::proto::cosmos::tx::v1beta1::{
    BroadcastTxRequest, BroadcastTxResponse, GetTxRequest, GetTxResponse, SimulateRequest,
    SimulateResponse,
};
use mockall::automock;
use report::ErrorExt;
use thiserror::Error;
use tonic::transport::Channel;
use tonic::Response;

type Result<T> = error_stack::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),
    #[error("failed to make the grpc request")]
    GrpcRequest(#[from] tonic::Status),
}

#[automock]
#[async_trait]
pub trait CosmosClient {
    async fn broadcast_tx(&mut self, req: BroadcastTxRequest) -> Result<BroadcastTxResponse>;
    async fn simulate(&mut self, req: SimulateRequest) -> Result<SimulateResponse>;
    async fn tx(&mut self, req: GetTxRequest) -> Result<GetTxResponse>;

    async fn account(&mut self, address: QueryAccountRequest) -> Result<QueryAccountResponse>;

    async fn balance(&mut self, request: QueryBalanceRequest) -> Result<QueryBalanceResponse>;
}

#[derive(Clone)]
pub struct CosmosGRpcClient {
    auth: AuthQueryClient<Channel>,
    bank: BankQueryClient<Channel>,
    service: ServiceClient<Channel>,
}

impl CosmosGRpcClient {
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
impl CosmosClient for CosmosGRpcClient {
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

use async_trait::async_trait;
use cosmrs::proto::cosmos::auth::v1beta1::query_client::QueryClient as AuthQueryClient;
use cosmrs::proto::cosmos::auth::v1beta1::{QueryAccountRequest, QueryAccountResponse};
use cosmrs::proto::cosmos::bank::v1beta1::query_client::QueryClient as BankQueryClient;
use cosmrs::proto::cosmos::bank::v1beta1::{QueryBalanceRequest, QueryBalanceResponse};
use cosmrs::proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmrs::proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmrs::proto::cosmos::tx::v1beta1::{
    BroadcastTxRequest, GetTxRequest, GetTxResponse, SimulateRequest, SimulateResponse,
};
use error_stack::{Report, Result};
use mockall::automock;
use tonic::transport::Channel;

use tonic::{Response, Status};

#[automock]
#[async_trait]
pub trait BroadcastClient {
    async fn broadcast_tx(&mut self, request: BroadcastTxRequest) -> Result<TxResponse, Status>;
    async fn simulate(&mut self, request: SimulateRequest) -> Result<SimulateResponse, Status>;
    async fn get_tx(&mut self, request: GetTxRequest) -> Result<GetTxResponse, Status>;
}

#[async_trait]
impl BroadcastClient for ServiceClient<Channel> {
    async fn broadcast_tx(&mut self, request: BroadcastTxRequest) -> Result<TxResponse, Status> {
        self.broadcast_tx(request)
            .await
            .and_then(|response| {
                response
                    .into_inner()
                    .tx_response
                    .ok_or_else(|| Status::not_found("tx not found"))
            })
            .map_err(Report::from)
    }

    async fn simulate(&mut self, request: SimulateRequest) -> Result<SimulateResponse, Status> {
        self.simulate(request)
            .await
            .map(Response::into_inner)
            .map_err(Report::from)
    }

    async fn get_tx(&mut self, request: GetTxRequest) -> Result<GetTxResponse, Status> {
        self.get_tx(request)
            .await
            .map(Response::into_inner)
            .map_err(Report::from)
    }
}

#[automock]
#[async_trait]
pub trait AccountQueryClient {
    async fn account(
        &mut self,
        request: QueryAccountRequest,
    ) -> Result<QueryAccountResponse, Status>;
}

#[async_trait]
impl AccountQueryClient for AuthQueryClient<Channel> {
    async fn account(
        &mut self,
        request: QueryAccountRequest,
    ) -> Result<QueryAccountResponse, Status> {
        return self
            .account(request)
            .await
            .map(Response::into_inner)
            .map_err(Report::from);
    }
}

#[automock]
#[async_trait]
pub trait BalanceQueryClient {
    async fn balance(
        &mut self,
        request: QueryBalanceRequest,
    ) -> Result<QueryBalanceResponse, Status>;
}

#[async_trait]
impl BalanceQueryClient for BankQueryClient<Channel> {
    async fn balance(
        &mut self,
        request: QueryBalanceRequest,
    ) -> Result<QueryBalanceResponse, Status> {
        self.balance(request)
            .await
            .map(|response| response.into_inner())
            .map_err(Report::from)
    }
}

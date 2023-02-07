use async_trait::async_trait;
use cosmos_sdk_proto::cosmos::auth::v1beta1::query_client::QueryClient;
use cosmos_sdk_proto::cosmos::auth::v1beta1::{QueryAccountRequest, QueryAccountResponse};
use cosmos_sdk_proto::cosmos::base::abci::v1beta1::TxResponse;
use cosmos_sdk_proto::cosmos::tx::v1beta1::service_client::ServiceClient;
use cosmos_sdk_proto::cosmos::tx::v1beta1::{
    BroadcastTxRequest, GetTxRequest, GetTxResponse, SimulateRequest, SimulateResponse,
};
use error_stack::{IntoReport, Result};
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
            .into_report()
    }

    async fn simulate(&mut self, request: SimulateRequest) -> Result<SimulateResponse, Status> {
        self.simulate(request).await.map(Response::into_inner).into_report()
    }

    async fn get_tx(&mut self, request: GetTxRequest) -> Result<GetTxResponse, Status> {
        self.get_tx(request).await.map(Response::into_inner).into_report()
    }
}

#[automock]
#[async_trait]
pub trait AccountQueryClient {
    async fn account(&mut self, request: QueryAccountRequest) -> Result<QueryAccountResponse, Status>;
}

#[async_trait]
impl AccountQueryClient for QueryClient<Channel> {
    async fn account(&mut self, request: QueryAccountRequest) -> Result<QueryAccountResponse, Status> {
        self.account(request).await.map(Response::into_inner).into_report()
    }
}

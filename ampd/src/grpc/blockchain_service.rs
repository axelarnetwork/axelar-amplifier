use std::pin::Pin;

use ampd_proto::blockchain_service_server::BlockchainService;
use ampd_proto::{
    AddressRequest, AddressResponse, BroadcastRequest, BroadcastResponse, ContractsRequest,
    ContractsResponse, QueryRequest, QueryResponse, SubscribeRequest, SubscribeResponse,
};
use async_trait::async_trait;
use futures::Stream;
use tonic::{Request, Response, Status};

pub struct Service {}

impl Service {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl BlockchainService for Service {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<SubscribeResponse, Status>> + Send + 'static>>;

    async fn subscribe(
        &self,
        _req: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        todo!("implement subscribe method")
    }

    async fn broadcast(
        &self,
        _req: Request<BroadcastRequest>,
    ) -> Result<Response<BroadcastResponse>, Status> {
        todo!("implement broadcast method")
    }

    async fn query(&self, _req: Request<QueryRequest>) -> Result<Response<QueryResponse>, Status> {
        todo!("implement query method")
    }

    async fn address(
        &self,
        _req: Request<AddressRequest>,
    ) -> Result<Response<AddressResponse>, Status> {
        todo!("implement address method")
    }

    async fn contracts(
        &self,
        _req: Request<ContractsRequest>,
    ) -> Result<Response<ContractsResponse>, Status> {
        todo!("implement contracts method")
    }
}

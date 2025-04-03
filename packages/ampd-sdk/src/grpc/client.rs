use async_trait::async_trait;
use error_stack::{Report, Result};
use mockall::automock;
use tonic::{codegen, transport, Status, Streaming};

use super::proto::blockchain_service_client::BlockchainServiceClient;
use super::proto::crypto_service_client::CryptoServiceClient;
use super::proto::{
    AddressRequest, AddressResponse, BroadcastRequest, BroadcastResponse, ContractsRequest,
    ContractsResponse, KeyRequest, KeyResponse, QueryRequest, QueryResponse, SignRequest,
    SignResponse, SubscribeRequest, SubscribeResponse,
};

#[automock]
#[async_trait]
pub trait GRPCClient {
    async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<Streaming<SubscribeResponse>, Status>;

    async fn broadcast(&self, request: BroadcastRequest) -> Result<BroadcastResponse, Status>;

    async fn query(&self, request: QueryRequest) -> Result<QueryResponse, Status>;

    async fn address(&self, request: AddressRequest) -> Result<AddressResponse, Status>;

    async fn contracts(&self, request: ContractsRequest) -> Result<ContractsResponse, Status>;

    async fn sign(&self, request: SignRequest) -> Result<SignResponse, Status>;

    async fn key(&self, request: KeyRequest) -> Result<KeyResponse, Status>;
}

pub struct Client {
    pub blockchain: BlockchainServiceClient<transport::Channel>,
    pub crypto: CryptoServiceClient<transport::Channel>,
}

pub async fn new<D>(dst: D) -> Result<Client, transport::Error>
where
    D: TryInto<transport::Endpoint>,
    D::Error: Into<codegen::StdError>,
{
    let conn = transport::Endpoint::new(dst)
        .map_err(Report::new)?
        .connect()
        .await
        .map_err(Report::new)?;

    let blockchain = BlockchainServiceClient::new(conn.clone());
    let crypto = CryptoServiceClient::new(conn);

    Ok(Client { blockchain, crypto })
}

#[async_trait]
impl GRPCClient for Client {
    async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<Streaming<SubscribeResponse>, Status> {
        todo!()
    }

    async fn broadcast(
        &self,
        request: BroadcastRequest,
    ) -> Result<BroadcastResponse, tonic::Status> {
        todo!()
    }

    async fn query(&self, request: QueryRequest) -> Result<QueryResponse, tonic::Status> {
        todo!()
    }

    async fn address(&self, request: AddressRequest) -> Result<AddressResponse, tonic::Status> {
        todo!()
    }

    async fn contracts(
        &self,
        request: ContractsRequest,
    ) -> Result<ContractsResponse, tonic::Status> {
        todo!()
    }

    async fn sign(&self, request: SignRequest) -> Result<SignResponse, tonic::Status> {
        todo!()
    }

    async fn key(&self, request: KeyRequest) -> Result<KeyResponse, tonic::Status> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_client() {
        let mut _mock = MockGRPCClient::new();

        // This test just verifies the mock can be created
        assert!(true);
    }
}

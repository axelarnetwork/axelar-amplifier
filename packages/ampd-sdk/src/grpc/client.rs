use async_trait::async_trait;
use error_stack::{Report, Result};
use mockall::automock;
use thiserror::Error;
use tonic::{transport, Streaming};

use super::proto::blockchain_service_client::BlockchainServiceClient;
use super::proto::crypto_service_client::CryptoServiceClient;
use super::proto::{SubscribeRequest, SubscribeResponse};

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GRpcConnection(#[from] tonic::transport::Error),

    #[error("failed to execute gRPC request")]
    GRpcRequest(#[from] tonic::Status),
}

#[automock]
#[async_trait]
#[allow(dead_code)]
pub trait Client {
    // TODO: This trait's methods should return our own types rather than the generated protobuf ones
    async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<Streaming<SubscribeResponse>, Error>;
}

#[allow(dead_code)]
pub struct GRPCClient {
    pub blockchain: BlockchainServiceClient<transport::Channel>,
    pub crypto: CryptoServiceClient<transport::Channel>,
}

#[allow(dead_code)]
pub async fn new(url: &str) -> Result<GRPCClient, Error> {
    let endpoint = transport::Endpoint::from_shared(url.to_string())
        .map_err(Into::into) // Convert to Error::GRpcConnection via #[from]
        .map_err(Report::new)?;

    let conn = endpoint
        .connect()
        .await
        .map_err(Into::into) // Convert to Error::GRpcConnection via #[from]
        .map_err(Report::new)?;

    let blockchain = BlockchainServiceClient::new(conn.clone());
    let crypto = CryptoServiceClient::new(conn);

    Ok(GRPCClient { blockchain, crypto })
}

#[async_trait]
#[allow(clippy::todo)]
impl Client for GRPCClient {
    async fn subscribe(
        &self,
        _request: SubscribeRequest,
    ) -> Result<Streaming<SubscribeResponse>, Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_client() {
        let mut _mock = MockClient::new();
        // This test just verifies the mock can be created
    }
}

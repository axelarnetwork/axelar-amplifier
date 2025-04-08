use async_trait::async_trait;
use error_stack::{Report, Result};
use mockall::automock;
use thiserror::Error;
use tonic::{codegen, transport, Streaming};

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
pub trait GRPCClient {
    // TODO: This trait's methods should return our own types raher than the generated protobuf ones
    async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<Streaming<SubscribeResponse>, Error>;
}

#[allow(dead_code)]
pub struct Client {
    pub blockchain: BlockchainServiceClient<transport::Channel>,
    pub crypto: CryptoServiceClient<transport::Channel>,
}

#[allow(dead_code)]
pub async fn new<D>(dst: D) -> Result<Client, Error>
where
    D: TryInto<transport::Endpoint>,
    D::Error: Into<codegen::StdError>,
{
    let conn = transport::Endpoint::new(dst)
        .map_err(|e| Report::new(Error::GRpcConnection(e)))?
        .connect()
        .await
        .map_err(|e| Report::new(Error::GRpcConnection(e)))?;

    let blockchain = BlockchainServiceClient::new(conn.clone());
    let crypto = CryptoServiceClient::new(conn);

    Ok(Client { blockchain, crypto })
}

#[async_trait]
#[allow(clippy::todo)]
impl GRPCClient for Client {
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
        let mut _mock = MockGRPCClient::new();
        // This test just verifies the mock can be created
    }
}

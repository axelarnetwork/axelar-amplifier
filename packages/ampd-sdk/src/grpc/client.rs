use std::pin::Pin;
use std::str::FromStr;
use std::vec;

use ampd_proto;
use ampd_proto::blockchain_service_client::BlockchainServiceClient;
use ampd_proto::crypto_service_client::CryptoServiceClient;
use ampd_proto::{AddressRequest, SubscribeRequest};
use async_trait::async_trait;
use cosmrs::AccountId;
use error_stack::{report, Report, Result, ResultExt};
use events::{AbciEventTypeFilter, Event};
use futures::StreamExt;
use mockall::automock;
use report::ErrorExt;
use thiserror::Error;
use tokio_stream::Stream;
use tonic::{transport, Request};

type AmpdBroadcasterAddress = AccountId;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),

    #[error("failed to execute gRPC request")]
    GrpcRequest(#[from] tonic::Status),

    #[error("failed to convert event")]
    EventConversion,

    #[error("failed to convert address")]
    AddressConversion,

    #[error("missing event in response")]
    InvalidResponse,
}

#[automock(type Stream = tokio_stream::Iter<vec::IntoIter<Result<Event, Error>>>;)]
#[async_trait]
#[allow(dead_code)]
pub trait Client {
    type Stream: Stream<Item = Result<Event, Error>>;

    async fn subscribe(
        &mut self,
        filters: Vec<AbciEventTypeFilter>,
        include_block_begin_end: bool,
    ) -> Result<Self::Stream, Error>;

    async fn address(&mut self) -> Result<AmpdBroadcasterAddress, Error>;
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct GrpcClient {
    pub blockchain: BlockchainServiceClient<transport::Channel>,
    pub crypto: CryptoServiceClient<transport::Channel>,
}

#[allow(dead_code)]
pub async fn new(url: &str) -> Result<GrpcClient, Error> {
    let endpoint: transport::Endpoint = url
        .parse()
        .map_err(Into::into) // Convert to Error::GrpcConnection via #[from]
        .map_err(Report::new)?;

    let conn = endpoint
        .connect()
        .await
        .map_err(Into::into) // Convert to Error::GrpcConnection via #[from]
        .map_err(Report::new)?;

    let blockchain = BlockchainServiceClient::new(conn.clone());
    let crypto = CryptoServiceClient::new(conn);

    Ok(GrpcClient { blockchain, crypto })
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
            .blockchain
            .subscribe(request)
            .await
            .map_err(Error::GrpcRequest)
            .map_err(Report::new)?;

        let transformed_stream = streaming_response.into_inner().map(|result| match result {
            Ok(response) => match response.event {
                Some(event) => Event::try_from(event).change_context(Error::EventConversion),
                None => Err(report!(Error::InvalidResponse)),
            },
            Err(e) => Err(report!(Error::GrpcRequest(e))),
        });

        Ok(Box::pin(transformed_stream))
    }

    async fn address(&mut self) -> Result<AmpdBroadcasterAddress, Error> {
        let broadcaster_address = self
            .blockchain
            .address(Request::new(AddressRequest {}))
            .await
            .map_err(ErrorExt::into_report)?
            .into_inner()
            .address;

        let ampd_broadcaster_address = AccountId::from_str(broadcaster_address.as_str())
            .map_err(|_| report!(Error::AddressConversion))?;

        Ok(ampd_broadcaster_address)
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

use std::collections::HashMap;

use async_trait::async_trait;
use error_stack::{Report, Result};
use events::Event;
use futures::StreamExt;
use mockall::automock;
use tendermint::block;
use thiserror::Error;
use tonic::{transport, Streaming};

use super::proto;
use super::proto::blockchain_service_client::BlockchainServiceClient;
use super::proto::crypto_service_client::CryptoServiceClient;
use super::proto::{subscribe_response, EventBlockBegin, EventBlockEnd};

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),

    #[error("failed to execute gRPC request")]
    GrpcRequest(#[from] tonic::Status),
}

#[automock]
#[async_trait]
#[allow(dead_code)]
pub trait Client {
    // TODO: This trait's methods should return our own types rather than the generated protobuf ones
    async fn subscribe(
        &self,
        filters: Vec<Event>,
        include_block_begin_end: bool,
    ) -> Result<Streaming<Event>, Error>;
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
#[allow(clippy::todo)]
impl Client for GrpcClient {
    async fn subscribe(
        &self,
        filters: Vec<Event>,
        include_block_begin_end: bool,
    ) -> Result<Streaming<Event>, Error> {
        let request = proto::SubscribeRequest {
            filters: filters
                .into_iter()
                .map(|event| proto::Event::from(event))
                .collect(),
            include_block_begin_end,
        };

        let streaming_response = self
            .blockchain
            .subscribe(request)
            .await
            .map_err(Into::into)
            .map_err(Report::new)?;

        let h = streaming_response.into_inner();

        let transformed_response = streaming_response
            .into_inner()
            .map(|proto_response| Event::from(proto_response.event.unwrap()))
            .collect(); 
        Ok(transformed_response) // this piece is still WIP, need to figure out a way to return vector of Event:event from SubscribeResponse:event 
    }
}

impl From<subscribe_response::Event> for Event {
    fn from(event: subscribe_response::Event) -> Self {
        match event {
            subscribe_response::Event::BlockBegin(block_start) => {
                Self::BlockBegin(block::Height::from(block_start.height as u32))
            } // might be problematic converting from u64 to u32
            subscribe_response::Event::BlockEnd(block_end) => {
                Self::BlockEnd(block::Height::from(block_end.height as u32))
            } // same issue
            subscribe_response::Event::Abci(abci) => Self::Abci {
                event_type: abci.r#type,
                attributes: convert_attributes(&abci.attributes),
            },
        }
    }
}

fn convert_attributes(
    proto_attrs: &HashMap<String, String>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut result = serde_json::Map::new();

    for (key, value) in proto_attrs {
        let json_value = serde_json::from_str(value)
            .unwrap_or_else(|_| serde_json::Value::String(value.clone()));

        result.insert(key.clone(), json_value);
    }

    result
}

impl From<Event> for proto::Event {
    fn from(event: Event) -> Self {
        let contract_address = if let Event::Abci { .. } = &event {
            event
                .contract_address()
                .map(|addr| addr.to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };

        let (event_type, attributes) = match event {
            Event::BlockBegin(_) | Event::BlockEnd(_) => {
                let type_name = if matches!(event, Event::BlockBegin(_)) {
                    "block_begin"
                } else {
                    "block_end"
                };
                (type_name.to_string(), HashMap::new())
            }
            Event::Abci {
                event_type,
                attributes,
            } => (
                event_type,
                attributes
                    .into_iter()
                    .map(|(key, value)| (key, value.to_string()))
                    .collect(),
            ),
        };

        Self {
            r#type: event_type,
            contract: contract_address,
            attributes,
        }
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

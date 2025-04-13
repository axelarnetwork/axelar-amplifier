use std::collections::HashMap;
use std::pin::Pin;

use async_trait::async_trait;
use error_stack::{Report, Result};
use events::Event;
use futures::StreamExt;
use mockall::automock;
use tendermint::block;
use thiserror::Error;
use tokio_stream::Stream;
use tonic::transport;

use super::proto;
use super::proto::blockchain_service_client::BlockchainServiceClient;
use super::proto::crypto_service_client::CryptoServiceClient;
use super::proto::subscribe_response;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),

    #[error("failed to execute gRPC request")]
    GrpcRequest(#[from] tonic::Status),

    #[error("failed to convert block height {block_height}")]
    BlockHeightConversion { block_height: u64 },

    #[error("missing event in response")]
    InvalidResponse,
}

type AbciEventTypeFilter = String;

#[automock(type Stream = tokio_stream::Iter<std::vec::IntoIter<Result<Event, Error>>>;)]
#[async_trait]
#[allow(dead_code)]
pub trait Client {
    type Stream: Stream<Item = Result<Event, Error>>;

    async fn subscribe(
        &mut self,
        filters: Vec<AbciEventTypeFilter>,
        include_block_begin_end: bool,
    ) -> Result<Self::Stream, Error>;
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
    type Stream = Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>;

    async fn subscribe(
        &mut self,
        filters: Vec<AbciEventTypeFilter>,
        include_block_begin_end: bool,
    ) -> Result<Self::Stream, Error> {
        let request = proto::SubscribeRequest {
            filters: filters.into_iter().map(proto::Event::from).collect(),
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
                Some(event) => match Event::try_from(event) {
                    Ok(converted_event) => Ok(converted_event),
                    Err(err) => Err(err),
                },
                None => Err(Report::new(Error::InvalidResponse)),
            },
            Err(e) => Err(Report::new(Error::GrpcRequest(e))),
        });

        Ok(Box::pin(transformed_stream))
    }
}

impl TryFrom<subscribe_response::Event> for Event {
    type Error = Report<Error>;

    fn try_from(event: subscribe_response::Event) -> Result<Event, Error> {
        match event {
            subscribe_response::Event::BlockBegin(block_start) => {
                block::Height::try_from(block_start.height)
                    .map_err(|_| {
                        Report::new(Error::BlockHeightConversion {
                            block_height: block_start.height,
                        })
                    })
                    .map(Self::BlockBegin)
            }
            subscribe_response::Event::BlockEnd(block_end) => {
                block::Height::try_from(block_end.height)
                    .map_err(|_| {
                        Report::new(Error::BlockHeightConversion {
                            block_height: block_end.height,
                        })
                    })
                    .map(Self::BlockEnd)
            }
            subscribe_response::Event::Abci(abci) => Ok(Self::Abci {
                event_type: abci.r#type,
                attributes: convert_attributes(&abci.attributes),
            }),
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

impl From<AbciEventTypeFilter> for proto::Event {
    fn from(event_type: AbciEventTypeFilter) -> Self {
        Self {
            r#type: event_type,
            contract: String::new(),
            attributes: HashMap::new(),
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

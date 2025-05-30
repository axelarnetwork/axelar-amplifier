use std::pin::Pin;
use std::vec;

use ampd_proto;
use ampd_proto::blockchain_service_client::BlockchainServiceClient;
use ampd_proto::crypto_service_client::CryptoServiceClient;
use ampd_proto::{
    AddressRequest, BroadcastRequest, BroadcastResponse, ContractStateRequest, ContractsRequest,
    ContractsResponse, SubscribeRequest,
};
use async_trait::async_trait;
use axelar_wasm_std::nonempty;
use cosmrs::AccountId;
use error_stack::{bail, Report, Result, ResultExt as _};
use events::{AbciEventTypeFilter, Event};
use futures::StreamExt;
use mockall::automock;
use report::{ResultCompatExt, ResultExt};
use thiserror::Error;
use tokio_stream::Stream;
use tonic::{transport, Request};

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] tonic::transport::Error),

    #[error("failed to execute gRPC request")]
    GrpcRequest(#[from] tonic::Status),

    #[error("failed to convert event")]
    EventConversion,

    #[error("invalid {0} address ")]
    InvalidAddress(&'static str),

    #[error("missing event in response")]
    InvalidResponse,

    #[error("query response is not valid json")]
    InvalidJson,

    #[error("invalid contracts response")]
    InvalidContractsResponse,
}

#[automock(type Stream = tokio_stream::Iter<vec::IntoIter<Result<Event, Error>>>;)]
#[async_trait]
pub trait Client {
    type Stream: Stream<Item = Result<Event, Error>>;

    async fn subscribe(
        &mut self,
        filters: Vec<AbciEventTypeFilter>,
        include_block_begin_end: bool,
    ) -> Result<Self::Stream, Error>;

    async fn address(&mut self) -> Result<AccountId, Error>;

    async fn broadcast(&mut self, msg: cosmrs::Any) -> Result<BroadcastClientResponse, Error>;

    async fn contract_state(
        &mut self,
        contract: nonempty::String,
        query: nonempty::Vec<u8>,
    ) -> Result<serde_json::Value, Error>;

    async fn contracts(&mut self) -> Result<ContractsAddresses, Error>;
}

#[derive(Clone)]
pub struct GrpcClient {
    pub blockchain: BlockchainServiceClient<transport::Channel>,
    pub crypto: CryptoServiceClient<transport::Channel>,
}

pub async fn new(url: &str) -> Result<GrpcClient, Error> {
    let endpoint: transport::Endpoint = url.parse().into_report()?; // Convert to Error::GrpcConnection via #[from]

    let conn = endpoint.connect().await.into_report()?;

    let blockchain = BlockchainServiceClient::new(conn.clone());
    let crypto = CryptoServiceClient::new(conn);

    Ok(GrpcClient { blockchain, crypto })
}

pub struct BroadcastClientResponse {
    pub tx_hash: String,
    pub index: u64,
}

impl From<BroadcastResponse> for BroadcastClientResponse {
    fn from(response: BroadcastResponse) -> Self {
        BroadcastClientResponse {
            tx_hash: response.tx_hash,
            index: response.index,
        }
    }
}

pub struct ContractsAddresses {
    pub voting_verifier: AccountId,
    pub multisig_prover: AccountId,
    pub service_registry: AccountId,
    pub rewards: AccountId,
}

impl TryFrom<&ContractsResponse> for ContractsAddresses {
    type Error = Report<Error>;

    fn try_from(
        response: &ContractsResponse,
    ) -> core::result::Result<ContractsAddresses, Self::Error> {
        Ok(ContractsAddresses {
            voting_verifier: response
                .voting_verifier
                .parse::<AccountId>()
                .change_context(Error::InvalidAddress("voting verifier"))?,
            multisig_prover: response
                .multisig_prover
                .parse::<AccountId>()
                .change_context(Error::InvalidAddress("multisig prover"))?,
            service_registry: response
                .service_registry
                .parse::<AccountId>()
                .change_context(Error::InvalidAddress("service registry"))?,
            rewards: response
                .rewards
                .parse::<AccountId>()
                .change_context(Error::InvalidAddress("rewards"))?,
        })
    }
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

        let streaming_response = self.blockchain.subscribe(request).await.into_report()?;

        let transformed_stream = streaming_response.into_inner().map(|result| match result {
            Ok(response) => match response.event {
                Some(event) => Event::try_from(event).change_context(Error::EventConversion),
                None => bail!(Error::InvalidResponse),
            },
            Err(e) => bail!(Error::GrpcRequest(e)),
        });

        Ok(Box::pin(transformed_stream))
    }

    async fn address(&mut self) -> Result<AccountId, Error> {
        let broadcaster_address = self
            .blockchain
            .address(Request::new(AddressRequest {}))
            .await
            .into_report()?
            .into_inner()
            .address;

        let ampd_broadcaster_address = broadcaster_address
            .parse::<AccountId>()
            .change_context(Error::InvalidAddress("broadcaster"))?;

        Ok(ampd_broadcaster_address)
    }

    async fn broadcast(&mut self, msg: cosmrs::Any) -> Result<BroadcastClientResponse, Error> {
        let request = BroadcastRequest { msg: Some(msg) };

        let broadcast_response = self
            .blockchain
            .broadcast(request)
            .await
            .into_report()?
            .into_inner();

        Ok(broadcast_response.into())
    }

    async fn contract_state(
        &mut self,
        contract: nonempty::String,
        query: nonempty::Vec<u8>,
    ) -> Result<serde_json::Value, Error> {
        self.blockchain
            .contract_state(ContractStateRequest {
                contract: contract.into(),
                query: query.into(),
            })
            .await
            .into_report()
            .map(|response| response.into_inner().result)
            .and_then(|result| {
                let encoded_response = hex::encode(&result);

                serde_json::to_value(result)
                    .change_context(Error::InvalidJson)
                    .attach_printable(encoded_response)
            })
    }

    async fn contracts(&mut self) -> Result<ContractsAddresses, Error> {
        let response = self
            .blockchain
            .contracts(Request::new(ContractsRequest {}))
            .await
            .into_report()?
            .into_inner();

        ContractsAddresses::try_from(&response)
            .change_context(Error::InvalidContractsResponse)
            .attach_printable(format!("{response:?}"))
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

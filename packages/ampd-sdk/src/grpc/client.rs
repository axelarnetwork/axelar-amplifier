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
use cosmwasm_std::Addr;
use error_stack::{report, Report, Result, ResultExt};
use events::{AbciEventTypeFilter, Event};
use futures::StreamExt;
use mockall::automock;
use report::ErrorExt;
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

    #[error("invalid address received")]
    InvalidAddress(#[from] cosmrs::ErrorReport),

    #[error("missing event in response")]
    InvalidResponse,

    #[error("empty query provided")]
    InvalidStateInput,
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

    async fn address(&mut self) -> Result<AccountId, Error>;

    async fn broadcast(&mut self, msg: cosmrs::Any) -> Result<BrodcastClientReponse, Error>;

    async fn contract_state(
        &mut self,
        contract: nonempty::String,
        query: Vec<u8>,
    ) -> Result<Vec<u8>, Error>;

    async fn contracts(&mut self) -> Result<ContractsAddresses, Error>;
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

pub struct BrodcastClientReponse {
    pub txhash: String,
    pub index: u64,
}

impl From<BroadcastResponse> for BrodcastClientReponse {
    fn from(response: BroadcastResponse) -> Self {
        BrodcastClientReponse {
            txhash: response.tx_hash,
            index: response.index,
        }
    }
}

pub struct ContractsAddresses {
    pub voting_verifier: Addr,
    pub multisig_prover: Addr,
    pub service_registry: Addr,
    pub rewards: Addr,
}

impl From<ContractsResponse> for ContractsAddresses {
    fn from(response: ContractsResponse) -> Self {
        ContractsAddresses {
            voting_verifier: Addr::unchecked(response.voting_verifier),
            multisig_prover: Addr::unchecked(response.multisig_prover),
            service_registry: Addr::unchecked(response.service_registry),
            rewards: Addr::unchecked(response.rewards),
        }
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

    async fn address(&mut self) -> Result<AccountId, Error> {
        let broadcaster_address = self
            .blockchain
            .address(Request::new(AddressRequest {}))
            .await
            .map_err(ErrorExt::into_report)?
            .into_inner()
            .address;

        let ampd_broadcaster_address =
            broadcaster_address.parse().map_err(ErrorExt::into_report)?;

        Ok(ampd_broadcaster_address)
    }

    async fn broadcast(&mut self, msg: cosmrs::Any) -> Result<BrodcastClientReponse, Error> {
        let request = BroadcastRequest { msg: Some(msg) };

        let broadcast_response = self
            .blockchain
            .broadcast(request)
            .await
            .map_err(ErrorExt::into_report)?
            .into_inner();

        Ok(broadcast_response.into())
    }

    async fn contract_state(
        &mut self,
        contract: nonempty::String,
        query: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        if query.is_empty() {
            return Err(report!(Error::InvalidStateInput));
        }

        self.blockchain
            .contract_state(ContractStateRequest {
                contract: contract.into(),
                query,
            })
            .await
            .map_err(ErrorExt::into_report)
            .map(|response| response.into_inner().result)
    }

    async fn contracts(&mut self) -> Result<ContractsAddresses, Error> {
        let response = self
            .blockchain
            .contracts(Request::new(ContractsRequest {}))
            .await
            .map_err(ErrorExt::into_report)?
            .into_inner();

        Ok(response.into())
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

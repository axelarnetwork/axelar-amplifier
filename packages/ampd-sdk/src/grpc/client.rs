use std::pin::Pin;
use std::vec;

use ampd_proto;
use ampd_proto::blockchain_service_client::BlockchainServiceClient;
use ampd_proto::crypto_service_client::CryptoServiceClient;
use ampd_proto::{
    AddressRequest, BroadcastRequest, BroadcastResponse, ContractStateRequest, ContractsRequest,
    ContractsResponse, KeyId, KeyRequest, SignRequest, SubscribeRequest,
};
use async_trait::async_trait;
use axelar_wasm_std::nonempty;
use cosmrs::AccountId;
use error_stack::{bail, Report, Result, ResultExt as _};
use events::{AbciEventTypeFilter, Event};
use futures::StreamExt;
use mockall::automock;
use report::{ResultCompatExt, ResultExt};
use serde::de::DeserializeOwned;
use tokio_stream::Stream;
use tonic::{transport, Request};

use crate::grpc::error::{AppError, Error};

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

    async fn contract_state<T: DeserializeOwned + 'static>(
        &mut self,
        contract: nonempty::String,
        query: nonempty::Vec<u8>,
    ) -> Result<T, Error>;

    async fn contracts(&mut self) -> Result<ContractsAddresses, Error>;

    async fn sign(
        &mut self,
        key: Option<Key>,
        message: nonempty::Vec<u8>,
    ) -> Result<nonempty::Vec<u8>, Error>;

    async fn key(&mut self, key: Option<Key>) -> Result<nonempty::Vec<u8>, Error>;
}

#[derive(Clone)]
pub struct GrpcClient {
    pub blockchain: BlockchainServiceClient<transport::Channel>,
    pub crypto: CryptoServiceClient<transport::Channel>,
}

pub async fn new(url: &str) -> Result<GrpcClient, Error> {
    let endpoint: transport::Endpoint = url.parse().into_report()?;
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
        let ContractsResponse {
            voting_verifier,
            multisig_prover,
            service_registry,
            rewards,
        } = response;

        Ok(ContractsAddresses {
            voting_verifier: parse_addr(voting_verifier, "voting verifier")?,
            multisig_prover: parse_addr(multisig_prover, "multisig prover")?,
            service_registry: parse_addr(service_registry, "service registry")?,
            rewards: parse_addr(rewards, "rewards contract")?,
        })
    }
}

fn parse_addr(addr: &str, address_name: &'static str) -> Result<AccountId, Error> {
    addr.parse::<AccountId>()
        .change_context(AppError::InvalidAddress(address_name).into())
        .attach_printable_lazy(|| addr.to_string())
}

pub struct Key {
    pub id: nonempty::String,
    pub algorithm: i32,
}

impl From<Key> for KeyId {
    fn from(key: Key) -> Self {
        KeyId {
            id: key.id.into(),
            algorithm: key.algorithm,
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

        let streaming_response = self.blockchain.subscribe(request).await.into_report()?;

        let transformed_stream = streaming_response.into_inner().map(|result| match result {
            Ok(response) => match response.event {
                Some(event) => {
                    Event::try_from(event).change_context(AppError::EventConversion.into())
                }
                None => bail!(Error::from(AppError::InvalidResponse)),
            },
            Err(status) => bail!(Error::from(status)),
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

        let ampd_broadcaster_address = parse_addr(&broadcaster_address, "broadcaster")?;
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

    async fn contract_state<T: DeserializeOwned + 'static>(
        &mut self,
        contract: nonempty::String,
        query: nonempty::Vec<u8>,
    ) -> Result<T, Error> {
        self.blockchain
            .contract_state(ContractStateRequest {
                contract: contract.into(),
                query: query.into(),
            })
            .await
            .into_report()
            .map(|response| response.into_inner().result)
            .and_then(|result| {
                serde_json::from_slice(&result)
                    .change_context(AppError::InvalidJson.into())
                    .attach_printable(hex::encode(&result))
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
            .change_context(AppError::InvalidContractsResponse.into())
            .attach_printable(format!("{response:?}"))
    }

    async fn sign(
        &mut self,
        key: Option<Key>,
        message: nonempty::Vec<u8>,
    ) -> Result<nonempty::Vec<u8>, Error> {
        self.crypto
            .sign(Request::new(SignRequest {
                key_id: key.map(|k| k.into()),
                msg: message.into(),
            }))
            .await
            .into_report()
            .and_then(|response| {
                nonempty::Vec::try_from(response.into_inner().signature)
                    .change_context(AppError::InvalidByteArray.into())
            })
    }

    async fn key(&mut self, key: Option<Key>) -> Result<nonempty::Vec<u8>, Error> {
        self.crypto
            .key(Request::new(KeyRequest {
                key_id: key.map(|k| k.into()),
            }))
            .await
            .into_report()
            .and_then(|response| {
                nonempty::Vec::try_from(response.into_inner().pub_key)
                    .change_context(AppError::InvalidByteArray.into())
            })
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

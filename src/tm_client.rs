use async_trait::async_trait;
use error_stack::{Report, Result};
use futures::TryFutureExt;

use tendermint::block::Height;
use tendermint_rpc::{Client, Subscription, SubscriptionClient, WebSocketClient};

use tokio_stream::Stream;

pub type BlockResponse = tendermint_rpc::endpoint::block_results::Response;
pub type TxResponse = tendermint_rpc::endpoint::broadcast::tx_sync::Response;
pub type RpcError = tendermint_rpc::Error;
pub type Query = tendermint_rpc::query::Query;
pub type Event = tendermint_rpc::event::Event;
pub type EventData = tendermint_rpc::event::EventData;
pub type EventType = tendermint_rpc::query::EventType;

#[async_trait]
pub trait TmClient {
    type Sub: Stream<Item = core::result::Result<Event, RpcError>> + Unpin;
    type Tx: Into<Vec<u8>>;

    async fn subscribe(&self, query: Query) -> Result<Self::Sub, RpcError>;
    async fn block_results(&self, block_height: Height) -> Result<BlockResponse, RpcError>;
    async fn broadcast(&self, tx_raw: Self::Tx) -> Result<TxResponse, RpcError>;
    fn close(self) -> Result<(), RpcError>;
}

#[async_trait]
impl TmClient for WebSocketClient {
    type Sub = Subscription;
    type Tx = Vec<u8>;

    async fn subscribe(&self, query: Query) -> Result<Self::Sub, RpcError> {
        SubscriptionClient::subscribe(self, query).map_err(Report::new).await
    }

    async fn block_results(&self, block_height: Height) -> Result<BlockResponse, RpcError> {
        Client::block_results(self, block_height).map_err(Report::new).await
    }
    async fn broadcast(&self, tx_raw: Self::Tx) -> Result<TxResponse, RpcError> {
        Client::broadcast_tx_sync(self, tx_raw).map_err(Report::new).await
    }
    fn close(self) -> Result<(), RpcError> {
        SubscriptionClient::close(self).map_err(Report::new)
    }
}

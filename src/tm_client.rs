use async_trait::async_trait;
use error_stack::{Report, Result};
use futures::TryFutureExt;

use tendermint::block::Height;
use tendermint_rpc::{Client, Subscription, SubscriptionClient, WebSocketClient};

use tokio_stream::Stream;

pub type BlockResultsResponse = tendermint_rpc::endpoint::block_results::Response;
pub type BlockResponse = tendermint_rpc::endpoint::block::Response;
pub type TxResponse = tendermint_rpc::endpoint::broadcast::tx_sync::Response;
pub type Error = tendermint_rpc::Error;
pub type Query = tendermint_rpc::query::Query;
pub type Event = tendermint_rpc::event::Event;
pub type EventData = tendermint_rpc::event::EventData;
pub type EventType = tendermint_rpc::query::EventType;

#[async_trait]
pub trait TmClient {
    type Sub: Stream<Item = core::result::Result<Event, Error>> + Unpin;
    type Tx: Into<Vec<u8>>;

    async fn subscribe(&self, query: Query) -> Result<Self::Sub, Error>;
    async fn latest_block(&self) -> Result<BlockResponse, Error>;
    async fn block_results(&self, block_height: Height) -> Result<BlockResultsResponse, Error>;
    async fn broadcast(&self, tx_raw: Self::Tx) -> Result<TxResponse, Error>;
    fn close(self) -> Result<(), Error>;
}

#[async_trait]
impl TmClient for WebSocketClient {
    type Sub = Subscription;
    type Tx = Vec<u8>;

    async fn subscribe(&self, query: Query) -> Result<Self::Sub, Error> {
        SubscriptionClient::subscribe(self, query).map_err(Report::new).await
    }

    async fn latest_block(&self) -> Result<BlockResponse, Error> {
        Client::latest_block(self).map_err(Report::new).await
    }

    async fn block_results(&self, block_height: Height) -> Result<BlockResultsResponse, Error> {
        Client::block_results(self, block_height).map_err(Report::new).await
    }

    async fn broadcast(&self, tx_raw: Self::Tx) -> Result<TxResponse, Error> {
        Client::broadcast_tx_sync(self, tx_raw).map_err(Report::new).await
    }

    fn close(self) -> Result<(), Error> {
        SubscriptionClient::close(self).map_err(Report::new)
    }
}

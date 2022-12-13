use std::collections::HashMap;

use async_trait::async_trait;
use error_stack::{FutureExt, Report, Result};
use error_stack::{IntoReport, ResultExt};
use futures::stream::StreamExt;
use futures::TryFutureExt;
use tendermint::abci::Event as AbciEvent;
use tendermint::block::Height;
use tendermint::Block;
use tendermint_rpc::endpoint::block_results::Response;
use tendermint_rpc::event::EventData;
use tendermint_rpc::query::{EventType, Query};
use tendermint_rpc::{Client, Error as RpcError, Subscription, SubscriptionClient, WebSocketClient};
use thiserror::Error;
use tokio::select;
use tokio::sync::{
    broadcast::{self, Sender},
    oneshot,
};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::Stream;

use crate::event_sub::EventSubError::*;

#[derive(Clone, Debug)]
pub struct Event {
    pub event_type: String,
    pub attributes: HashMap<String, String>,
}

impl From<AbciEvent> for Event {
    fn from(event: AbciEvent) -> Self {
        Self {
            event_type: event.kind,
            attributes: event.attributes.into_iter().map(|tag| (tag.key, tag.value)).collect(),
        }
    }
}

#[async_trait]
pub trait TmClient {
    type Sub: Stream<Item = core::result::Result<tendermint_rpc::event::Event, RpcError>> + Unpin;

    async fn subscribe(&self, query: Query) -> Result<Self::Sub, RpcError>;
    async fn block_results(&self, block_height: Height) -> Result<Response, RpcError>;
    fn close(self) -> Result<(), RpcError>;
}

#[async_trait]
impl TmClient for WebSocketClient {
    type Sub = Subscription;

    async fn subscribe(&self, query: Query) -> Result<Self::Sub, RpcError> {
        SubscriptionClient::subscribe(self, query).map_err(Report::new).await
    }

    async fn block_results(&self, block_height: Height) -> Result<Response, RpcError> {
        Client::block_results(self, block_height).map_err(Report::new).await
    }

    fn close(self) -> Result<(), RpcError> {
        SubscriptionClient::close(self).map_err(Report::new)
    }
}

pub struct EventSubClientDriver {
    close_tx: oneshot::Sender<()>,
}

impl EventSubClientDriver {
    pub fn close(self) -> Result<(), EventSubError> {
        self.close_tx.send(()).map_err(|_| Report::new(CloseFailed))
    }
}

pub struct EventSubClient<T: TmClient + Sync> {
    client: T,
    capacity: usize,
    tx: Option<Sender<Event>>,
    close_rx: oneshot::Receiver<()>,
}

impl<T: TmClient + Sync> EventSubClient<T> {
    pub fn new(client: T, capacity: usize) -> (Self, EventSubClientDriver) {
        let (close_tx, close_rx) = oneshot::channel();
        let client_driver = EventSubClientDriver { close_tx };
        let client = EventSubClient {
            client,
            capacity,
            tx: None,
            close_rx,
        };

        (client, client_driver)
    }

    pub fn sub(&mut self) -> BroadcastStream<Event> {
        let rx = match &self.tx {
            None => {
                let (tx, rx) = broadcast::channel::<Event>(self.capacity);
                self.tx = Some(tx);
                rx
            }
            Some(tx) => tx.subscribe(),
        };

        BroadcastStream::new(rx)
    }

    pub async fn run(mut self) -> Result<(), EventSubError> {
        match &self.tx {
            None => Err(Report::new(NoSubscriber)),
            Some(tx) => {
                let mut sub = self
                    .client
                    .subscribe(EventType::NewBlock.into())
                    .change_context(SubscriptionFailed)
                    .await?;

                loop {
                    select! {
                        res = sub.next() => {
                            if res.is_none() {
                                break;
                            }

                            let event = res.unwrap().into_report().change_context(StreamFailed)?;
                            if let EventData::NewBlock { block: Some(block), .. } = event.data {
                                let height = block.header().height;
                                self.process_block(tx, block)
                                    .attach_printable(format!("{{ block_height = {height} }}"))
                                    .await?;
                            }
                        },
                        _ = &mut self.close_rx => break,
                    }
                }

                self.client.close().change_context(CloseFailed)?;
                Ok(())
            }
        }
    }

    // this is extracted into a function so the block height attachment can be added no matter which call fails
    async fn process_block(&self, tx: &Sender<Event>, block: Block) -> Result<(), EventSubError> {
        for event in self.query_events(block.header().height).await? {
            tx.send(event.into()).into_report().change_context(PublishFailed)?;
        }

        Ok(())
    }

    async fn query_events(&self, block_height: Height) -> Result<Vec<AbciEvent>, EventSubError> {
        let block_results = self
            .client
            .block_results(block_height)
            .change_context(EventQueryFailed { block: block_height })
            .await?;

        let begin_block_events = block_results.begin_block_events.into_iter().flatten();
        let tx_events = block_results.txs_results.into_iter().flatten().flat_map(|tx| tx.events);
        let end_block_events = block_results.end_block_events.into_iter().flatten();

        Ok(begin_block_events.chain(tx_events).chain(end_block_events).collect())
    }
}

#[derive(Error, Debug)]
pub enum EventSubError {
    #[error("no subscriber")]
    NoSubscriber,
    #[error("subscription failed")]
    SubscriptionFailed,
    #[error("stream failed")]
    StreamFailed,
    #[error("querying events for block {block} failed")]
    EventQueryFailed { block: Height },
    #[error("failed to send events to subscribers")]
    PublishFailed,
    #[error("failed closing client")]
    CloseFailed,
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use error_stack::{IntoReport, Result};
    use futures::stream::StreamExt;
    use futures::Stream;
    use mockall::mock;
    use mockall::predicate;
    use tendermint::block::Height;
    use tendermint_rpc::endpoint::block_results::Response;
    use tendermint_rpc::query::Query;
    use tendermint_rpc::Error as RpcError;
    use tokio::sync::oneshot;
    use tokio::test;

    use crate::event_sub::EventSubError;
    use crate::event_sub::{EventSubClient, TmClient};

    #[test]
    async fn no_subscriber() {
        let (client, _) = EventSubClient::new(MockWebsocketClient::new(), 10);
        let res = client.run().await;
        assert!(matches!(
            res.unwrap_err().current_context(),
            EventSubError::NoSubscriber
        ));
    }

    #[test]
    async fn subscription_failed() {
        let mut mock_client = MockWebsocketClient::new();
        mock_client
            .expect_subscribe()
            .returning(|_| Err(RpcError::client_internal("internal failure".into())).into_report());
        let (mut client, _) = EventSubClient::new(mock_client, 10);
        let _ = client.sub();
        let res = client.run().await;
        assert!(matches!(
            res.unwrap_err().current_context(),
            EventSubError::SubscriptionFailed
        ));
    }

    #[test]
    async fn close_works() {
        let mut mock_client = MockWebsocketClient::new();
        let block: tendermint::Block = serde_json::from_str(include_str!("../tests/fixtures/block.json")).unwrap();
        let block_height = block.header().height;
        let block_results: tendermint_rpc::endpoint::block_results::Response =
            serde_json::from_str(include_str!("../tests/fixtures/block_results.json")).unwrap();

        let begin_block_events = block_results.begin_block_events.clone().into_iter().flatten();
        let tx_events = block_results
            .txs_results
            .clone()
            .into_iter()
            .flatten()
            .flat_map(|tx| tx.events);
        let end_block_events = block_results.end_block_events.clone().into_iter().flatten();
        let event_count = begin_block_events.count() + tx_events.count() + end_block_events.count();

        mock_client.expect_subscribe().returning(move |_| {
            let mut mock_subscription = MockSubscription::new();
            let mut poll_count = 0;
            let block = block.clone();

            mock_subscription.expect_poll_next().returning(move |_| {
                poll_count += 1;

                match poll_count {
                    1 => core::task::Poll::Ready(Some(Ok(tendermint_rpc::event::Event {
                        query: "".into(),
                        data: tendermint_rpc::event::EventData::NewBlock {
                            block: Some(block.clone()),
                            result_begin_block: None,
                            result_end_block: None,
                        },
                        events: None,
                    }))),
                    _ => core::task::Poll::Pending,
                }
            });

            Ok(mock_subscription)
        });
        mock_client
            .expect_block_results()
            .once()
            .with(predicate::eq(block_height))
            .returning(move |_| Ok(block_results.clone()));
        mock_client.expect_close().once().returning(|| Ok(()));

        let (done_tx, done_rx) = oneshot::channel::<()>();

        let (mut client, client_driver) = EventSubClient::new(mock_client, event_count);
        let mut event_stream = client.sub();
        let event_stream_handle = tokio::spawn(async move {
            let mut count = 0;

            loop {
                if let Some(Ok(_)) = event_stream.next().await {
                    count += 1;
                }

                if count == event_count {
                    break;
                }
            }

            done_tx.send(()).unwrap();
            assert!(event_stream.next().await.is_none());
        });
        let client_handle = tokio::spawn(async move { client.run().await });

        assert!(done_rx.await.is_ok());
        assert!(client_driver.close().is_ok());
        assert!(client_handle.await.is_ok());
        assert!(event_stream_handle.await.is_ok());
    }

    mock! {
            Subscription{}

            impl Stream for Subscription {
                type Item = core::result::Result<tendermint_rpc::event::Event, RpcError>;

                fn poll_next<'a>(self: Pin<&mut Self>, cx: &mut Context<'a>) -> Poll<Option<<Self as Stream>::Item>>;
            }
    }

    mock! {
        WebsocketClient{}

        #[async_trait]
        impl TmClient for WebsocketClient{
            type Sub = MockSubscription;

            async fn subscribe(&self, query: Query) -> Result<<Self as TmClient>::Sub, RpcError>;
            async fn block_results(&self, block_height: Height) -> Result<Response, RpcError>;
            fn close(self) -> Result<(), RpcError>;
        }
    }
}

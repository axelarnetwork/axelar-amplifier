use std::time::Duration;

use error_stack::{FutureExt, Report, Result};
use error_stack::{IntoReport, ResultExt};
use tendermint::abci;
use tendermint::block;
use thiserror::Error;
use tokio::select;
use tokio::sync::{
    broadcast::{self, Sender},
    oneshot,
};
use tokio::time;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

use crate::event_sub::EventSubError::*;
use crate::tm_client::TmClient;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    BlockEnd(block::Height),
    Abci {
        event_type: String,
        attributes: serde_json::Map<String, serde_json::Value>,
    },
}

impl From<abci::Event> for Event {
    fn from(event: abci::Event) -> Self {
        Self::Abci {
            event_type: event.kind,
            attributes: event
                .attributes
                .into_iter()
                .map(
                    |abci::EventAttribute { key, value, .. }| match serde_json::from_str(&value) {
                        Ok(v) => (key, v),
                        Err(_) => (key, value.into()),
                    },
                )
                .collect(),
        }
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
    start_from: Option<block::Height>,
    poll_interval: Duration,
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
            start_from: None,
            poll_interval: Duration::new(5, 0),
            tx: None,
            close_rx,
        };

        (client, client_driver)
    }

    pub fn start_from(mut self, height: block::Height) -> Self {
        self.start_from = Some(height);
        self
    }

    #[allow(dead_code)]
    pub fn poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    pub fn sub(&mut self) -> impl Stream<Item = Result<Event, BroadcastStreamRecvError>> {
        let rx = match &self.tx {
            None => {
                let (tx, rx) = broadcast::channel::<Event>(self.capacity);
                self.tx = Some(tx);
                rx
            }
            Some(tx) => tx.subscribe(),
        };

        BroadcastStream::new(rx).map(IntoReport::into_report)
    }

    pub async fn run(mut self) -> Result<(), EventSubError> {
        match &self.tx {
            None => Err(Report::new(NoSubscriber)),
            Some(tx) => {
                let mut curr_block_height = match self.start_from {
                    Some(start_from) => start_from,
                    None => self.get_latest_block_height().await?,
                };
                let mut interval = time::interval(self.poll_interval);

                loop {
                    select! {
                        _ = interval.tick() => {
                            let latest_block_height = self.get_latest_block_height().await?;
                            self.process_blocks(tx, curr_block_height, latest_block_height).await?;
                            curr_block_height = latest_block_height.increment();
                        },
                        _ = &mut self.close_rx => return Ok(()),
                    }
                }
            }
        }
    }

    async fn get_latest_block_height(&self) -> Result<block::Height, EventSubError> {
        let res = self.client.latest_block().change_context(RPCFailed).await?;

        Ok(res.block.header().height)
    }

    // this is extracted into a function so the block height attachment can be added no matter which call fails
    async fn process_blocks(
        &self,
        tx: &Sender<Event>,
        from: block::Height,
        to: block::Height,
    ) -> Result<(), EventSubError> {
        let mut height = from;
        while height <= to {
            self.process_block(tx, height)
                .attach_printable(format!("{{ block_height = {height} }}"))
                .await?;
            height = height.increment();
        }

        Ok(())
    }

    async fn process_block(&self, tx: &Sender<Event>, height: block::Height) -> Result<(), EventSubError> {
        for event in self.query_events(height).await? {
            tx.send(event.into()).into_report().change_context(PublishFailed)?;
        }
        tx.send(Event::BlockEnd(height))
            .into_report()
            .change_context(PublishFailed)?;

        Ok(())
    }

    async fn query_events(&self, block_height: block::Height) -> Result<Vec<abci::Event>, EventSubError> {
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

pub fn skip_to_block(
    stream: impl Stream<Item = Result<Event, BroadcastStreamRecvError>>,
    height: block::Height,
) -> impl Stream<Item = Result<Event, BroadcastStreamRecvError>> {
    stream.skip_while(move |event| !matches!(event, Ok(Event::BlockEnd(h)) if h.increment() >= height))
}

#[derive(Error, Debug)]
pub enum EventSubError {
    #[error("no subscriber")]
    NoSubscriber,
    #[error("querying events for block {block} failed")]
    EventQueryFailed { block: block::Height },
    #[error("failed to send events to subscribers")]
    PublishFailed,
    #[error("failed calling RPC method")]
    RPCFailed,
    #[error("failed closing client")]
    CloseFailed,
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::time::Duration;

    use futures::stream::StreamExt;
    use rand::Rng;
    use random_string::generate;
    use tendermint::abci;
    use tokio::test;

    use crate::event_sub::{Event, EventSubClient, EventSubError};
    use crate::tm_client;

    #[test]
    async fn no_subscriber() {
        let (client, _) = EventSubClient::new(tm_client::MockTmClient::new(), 10);

        assert!(matches!(
            client.run().await.unwrap_err().current_context(),
            EventSubError::NoSubscriber
        ));
    }

    #[test]
    async fn start_from_should_work() {
        let block_count = 10;
        let block: tendermint::Block = serde_json::from_str(include_str!("../tests/fixtures/block.json")).unwrap();
        let from_height = (block.header.height.value() - block_count + 1).try_into().unwrap();
        let to_height = block.header.height;

        let mut mock_client = tm_client::MockTmClient::new();
        mock_client.expect_latest_block().once().returning(move || {
            Ok(tm_client::BlockResponse {
                block_id: Default::default(),
                block: block.clone(),
            })
        });
        mock_client
            .expect_block_results()
            .times(block_count as usize)
            .returning(|height| {
                Ok(tm_client::BlockResultsResponse {
                    height,
                    begin_block_events: None,
                    end_block_events: None,
                    consensus_param_updates: None,
                    txs_results: None,
                    validator_updates: vec![],
                })
            });

        let (client, driver) = EventSubClient::new(mock_client, 2 * block_count as usize);
        let mut client = client.start_from(from_height);
        let mut stream = client.sub();

        let handle = tokio::spawn(async move { client.run().await });

        for height in from_height.value()..to_height.value() {
            let event = stream.next().await;
            assert_eq!(event.unwrap().unwrap(), Event::BlockEnd(height.try_into().unwrap()));
        }

        assert!(driver.close().is_ok());
        assert!(handle.await.is_ok());
    }

    #[test]
    async fn should_start_from_latest_when_none_is_given() {
        let block: tendermint::Block = serde_json::from_str(include_str!("../tests/fixtures/block.json")).unwrap();
        let height = block.header.height;

        let mut mock_client = tm_client::MockTmClient::new();
        mock_client.expect_latest_block().times(2).returning(move || {
            Ok(tm_client::BlockResponse {
                block_id: Default::default(),
                block: block.clone(),
            })
        });
        mock_client.expect_block_results().once().returning(|height| {
            Ok(tm_client::BlockResultsResponse {
                height,
                begin_block_events: None,
                end_block_events: None,
                consensus_param_updates: None,
                txs_results: None,
                validator_updates: vec![],
            })
        });

        let (mut client, driver) = EventSubClient::new(mock_client, 10);
        let mut stream = client.sub();

        let handle = tokio::spawn(async move { client.run().await });

        let event = stream.next().await;
        assert_eq!(event.unwrap().unwrap(), Event::BlockEnd(height));

        assert!(driver.close().is_ok());
        assert!(handle.await.is_ok());
    }

    #[test]
    async fn stream_should_work() {
        let block_count = 10;
        let block: tendermint::Block = serde_json::from_str(include_str!("../tests/fixtures/block.json")).unwrap();
        let block_height = block.header.height;
        let mut rng = rand::thread_rng();
        let block_results = tm_client::BlockResultsResponse {
            height: block_height,
            begin_block_events: vec![0; rng.gen_range(0..20)]
                .into_iter()
                .map(|_| Some(random_event()))
                .collect(),
            end_block_events: vec![0; rng.gen_range(0..20)]
                .into_iter()
                .map(|_| Some(random_event()))
                .collect(),
            consensus_param_updates: None,
            txs_results: Some(
                vec![0; rng.gen_range(0..20)]
                    .into_iter()
                    .map(|_| abci::response::DeliverTx {
                        events: vec![0; rng.gen_range(0..20)]
                            .into_iter()
                            .map(|_| random_event())
                            .collect(),
                        ..Default::default()
                    })
                    .collect(),
            ),
            validator_updates: vec![],
        };
        let begin_block_events_count = block_results.begin_block_events.iter().flatten().count();
        let tx_events_count: usize = block_results
            .txs_results
            .iter()
            .flatten()
            .map(|tx| tx.events.len())
            .sum();
        let end_block_events = block_results.end_block_events.iter().flatten().count();
        let event_count_per_block = begin_block_events_count + tx_events_count + end_block_events + 1;

        let mut mock_client = tm_client::MockTmClient::new();
        let mut latest_block_call_count = 0;
        mock_client.expect_latest_block().times(block_count).returning(move || {
            let mut block = block.clone();
            block.header.height = (block_height.value() + latest_block_call_count).try_into().unwrap();

            latest_block_call_count += 1;
            Ok(tm_client::BlockResponse {
                block_id: Default::default(),
                block,
            })
        });
        mock_client
            .expect_block_results()
            .times(block_count)
            .returning(move |height| {
                let mut block_results = block_results.clone();
                block_results.height = height;

                Ok(block_results)
            });

        let (client, driver) = EventSubClient::new(mock_client, block_count * event_count_per_block);
        let mut client = client
            .start_from(block_height)
            .poll_interval(Duration::new(0, 1e8 as u32));
        let mut stream = client.sub();

        let handle = tokio::spawn(async move { client.run().await });

        for i in 1..(block_count * event_count_per_block + 1) {
            let event = stream.next().await;
            match i % event_count_per_block {
                0 => {
                    assert!(matches!(event, Some(Ok(Event::BlockEnd(..)))));
                }
                _ => {
                    assert!(matches!(event, Some(Ok(Event::Abci { .. }))));
                }
            }
        }

        assert!(driver.close().is_ok());
        assert!(handle.await.is_ok());
    }

    fn random_event() -> abci::Event {
        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        abci::Event::new(
            generate(10, charset),
            vec![abci::EventAttribute {
                key: generate(10, charset),
                value: generate(10, charset),
                index: false,
            }],
        )
    }
}

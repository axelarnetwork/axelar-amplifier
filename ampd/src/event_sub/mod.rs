use std::time::Duration;

use error_stack::{Report, Result};
use events::Event;
use futures::{future, StreamExt, TryStreamExt};
use mockall::automock;
use report::LoggableError;
use tendermint::block;
use thiserror::Error;
use tokio::sync::broadcast::{self, Sender};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, instrument};
use valuable::Valuable;

use crate::asyncutil::future::RetryPolicy;
use crate::monitoring;
use crate::monitoring::metrics::Msg;
use crate::tm_client::TmClient;

pub mod stream;

// The maximum number of blocks to process concurrently.
// - A value of 1 ensures sequential processing, preventing the event sub
//   from downloading events from multiple blocks simultaneously. This minimizes
//   memory usage but may slow down event processing.
// - Higher values enable parallel block processing, improving throughput but
//   increasing memory usage and potential resource contention.
// - Setting this too high may cause excessive memory consumption, while setting
//   it too low may lead to slower processing and underutilization of downstream
//   consumers.
const BLOCK_PROCESSING_BUFFER: usize = 10;
// Interval to poll for new blocks
const POLL_INTERVAL: Duration = Duration::from_secs(5);
// Retry policy for block processing and event retrival
const BLOCK_PROCESSING_RETRY_POLICY: RetryPolicy = RetryPolicy::RepeatConstant {
    sleep: Duration::from_secs(3),
    max_attempts: 3,
};

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("failed querying the latest block")]
    LatestBlockQuery,
    #[error("failed querying the block results for block {block}")]
    BlockResultsQuery { block: block::Height },
    #[error("failed decoding event in block {block}")]
    EventDecoding { block: block::Height },
    #[error("failed receiving event from broadcast stream")]
    BroadcastStreamRecv(#[from] BroadcastStreamRecvError),
}

#[automock]
pub trait EventSub {
    fn subscribe(&self) -> impl Stream<Item = Result<Event, Error>> + Send + 'static;
}

#[derive(Clone, Debug)]
pub struct EventSubscriber {
    tx: Sender<std::result::Result<Event, Error>>,
}

impl EventSub for EventSubscriber {
    fn subscribe(&self) -> impl Stream<Item = Result<Event, Error>> + 'static {
        BroadcastStream::new(self.tx.subscribe())
            .map(|event| match event {
                Ok(Ok(event)) => Ok(event),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(err.into()),
            })
            .map_err(Report::from)
    }
}

#[derive(Debug)]
pub struct EventPublisher<T: TmClient + Sync> {
    tm_client: T,
    poll_interval: Duration,
    tx: Sender<std::result::Result<Event, Error>>,
    delay: Duration,
    monitoring_client: monitoring::Client,
}

impl<T: TmClient + Sync + std::fmt::Debug> EventPublisher<T> {
    #[instrument]
    pub fn new(
        client: T,
        capacity: usize,
        delay: Duration,
        monitoring_client: monitoring::Client,
    ) -> (Self, EventSubscriber) {
        let (tx, _) = broadcast::channel(capacity);
        let publisher = EventPublisher {
            tm_client: client,
            poll_interval: POLL_INTERVAL,
            tx: tx.clone(),
            delay,
            monitoring_client,
        };
        let subscriber = EventSubscriber { tx };

        (publisher, subscriber)
    }

    #[instrument]
    pub async fn run(self, token: CancellationToken) -> Result<(), Error> {
        let block_stream = stream::blocks(&self.tm_client, self.poll_interval, self.delay)
            .filter(|_| future::ready(self.has_subscriber())); // skip processing blocks when no subscriber exists
        let event_stream =
            stream::events(&self.tm_client, block_stream, BLOCK_PROCESSING_RETRY_POLICY)
                .take_until(token.cancelled());

        tokio::pin!(event_stream);
        while let Some(event) = event_stream.next().await {
            // error_stack::Report does not implement `Clone`, so we log the full error and pass on the latest context
            let event = event
                .inspect_err(|err| {
                    self.monitoring_client
                        .metrics()
                        .record_metric(Msg::EventPublisherError);

                    error!(
                        err = LoggableError::from(err).as_value(),
                        "failed to retrieve to events"
                    );
                })
                .map_err(|err| err.current_context().clone());

            let _ = self.tx.send(event).map_err(Report::new).inspect_err(|err| {
                self.monitoring_client
                    .metrics()
                    .record_metric(Msg::EventPublisherError);

                error!(
                    err = LoggableError::from(err).as_value(),
                    "failed to send event to subscribers"
                );
            });
        }

        info!("exiting event sub");

        Ok(())
    }

    fn has_subscriber(&self) -> bool {
        self.tx.receiver_count() > 0
    }
}

#[cfg(test)]
mod tests {
    use std::sync;
    use std::time::Duration;

    use axelar_wasm_std::assert_err_contains;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use error_stack::report;
    use events::Event;
    use futures::stream::StreamExt;
    use random_string::generate;
    use tendermint::{abci, block};
    use tokio_util::sync::CancellationToken;

    use crate::event_sub::{Error, EventPublisher, EventSub};
    use crate::monitoring::metrics::Msg;
    use crate::monitoring::test_utils;
    use crate::tm_client::{self, MockTmClient};

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn should_skip_processing_blocks_when_no_subscriber_exists() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let mut height = block.header().height;

        let mut tm_client = MockTmClient::new();
        let call_count = sync::Arc::new(sync::RwLock::new(0));
        let inner_call_count = call_count.clone();
        tm_client.expect_latest_block().returning(move || {
            *inner_call_count.write().unwrap() += 1;

            let mut block = block.clone();
            height = height.increment();
            block.header.height = height;

            Ok(tm_client::BlockResponse {
                block_id: Default::default(),
                block,
            })
        });
        tm_client.expect_block_results().never();

        let token = CancellationToken::new();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let (event_publisher, _subscriber) =
            EventPublisher::new(tm_client, 100, Duration::from_secs(1), monitoring_client);
        let handle = tokio::spawn(event_publisher.run(token.child_token()));

        while *call_count.read().unwrap() < 10 {
            tokio::time::advance(Duration::from_secs(1)).await;
        }

        token.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn should_stream_events_and_errors() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let initial_height = block.header().height;

        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;
        let mut height = initial_height;
        tm_client.expect_latest_block().returning(move || {
            call_count += 1;

            match call_count {
                1 => Ok(tm_client::BlockResponse {
                    block_id: Default::default(),
                    block: block.clone(),
                }),
                2 => Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                ))),
                _ => {
                    let mut block = block.clone();
                    height = height.increment();
                    block.header.height = height;

                    Ok(tm_client::BlockResponse {
                        block_id: Default::default(),
                        block,
                    })
                }
            }
        });
        tm_client.expect_block_results().returning(move |height| {
            if height == initial_height {
                Ok(block_results_response(
                    height,
                    vec![random_event()],
                    vec![random_event()],
                    vec![random_event()],
                ))
            } else if height == initial_height.increment() {
                Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                )))
            } else {
                Ok(block_results_response(height, vec![], vec![], vec![]))
            }
        });

        let token = CancellationToken::new();
        let (monitoring_client, _) = test_utils::monitoring_client();
        let (event_publisher, subscriber) =
            EventPublisher::new(tm_client, 100, Duration::from_secs(1), monitoring_client);
        let mut stream = subscriber.subscribe();
        let handle = tokio::spawn(event_publisher.run(token.child_token()));

        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockBegin(_))
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::Abci { .. })
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::Abci { .. })
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::Abci { .. })
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockEnd(_))
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_err_contains!(
            stream.next().await.unwrap(),
            Error,
            Error::BlockResultsQuery { .. }
        );
        tokio::time::advance(Duration::from_secs(1)).await;

        token.cancel();
        handle.await.unwrap().unwrap();
    }

    pub fn random_event() -> abci::Event {
        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        abci::Event::new(
            generate(10, charset),
            vec![abci::EventAttribute {
                key: STANDARD.encode(generate(10, charset)),
                value: STANDARD.encode(generate(10, charset)),
                index: false,
            }],
        )
    }

    pub fn block_results_response(
        height: block::Height,
        begin_block_events: Vec<abci::Event>,
        end_block_events: Vec<abci::Event>,
        txs_events: Vec<abci::Event>,
    ) -> tm_client::BlockResultsResponse {
        tm_client::BlockResultsResponse {
            height,
            begin_block_events: Some(begin_block_events),
            end_block_events: Some(end_block_events),
            consensus_param_updates: None,
            txs_results: Some(
                txs_events
                    .into_iter()
                    .map(|event| abci::types::ExecTxResult {
                        events: vec![event],
                        ..Default::default()
                    })
                    .collect(),
            ),
            validator_updates: vec![],
            app_hash: Default::default(),
            finalize_block_events: vec![],
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn should_record_event_publisher_err_successfully() {
        let block: tendermint::Block =
            serde_json::from_str(include_str!("../tests/axelar_block.json")).unwrap();
        let initial_height = block.header().height;

        let mut tm_client = MockTmClient::new();
        let mut call_count = 0;
        tm_client.expect_latest_block().returning(move || {
            call_count += 1;

            match call_count {
                1 => Err(report!(tendermint_rpc::Error::server(
                    "server error".to_string()
                ))),
                2 => Ok(tm_client::BlockResponse {
                    block_id: Default::default(),
                    block: block.clone(),
                }),
                _ => unreachable!("Should only have 2 calls"),
            }
        });
        tm_client.expect_block_results().returning(move |height| {
            if height == initial_height {
                Ok(block_results_response(
                    height,
                    vec![random_event()],
                    vec![random_event()],
                    vec![random_event()],
                ))
            } else {
                Ok(block_results_response(height, vec![], vec![], vec![]))
            }
        });

        let token = CancellationToken::new();
        let (monitoring_client, mut receiver) = test_utils::monitoring_client();
        let (event_publisher, subscriber) =
            EventPublisher::new(tm_client, 100, Duration::from_secs(1), monitoring_client);
        let mut stream = subscriber.subscribe();
        let handle = tokio::spawn(event_publisher.run(token.child_token()));

        assert_err_contains!(stream.next().await.unwrap(), Error, Error::LatestBlockQuery);
        tokio::time::advance(Duration::from_secs(1)).await;

        let metric = receiver.recv().await.unwrap();
        assert_eq!(metric, Msg::EventPublisherError);

        assert!(matches!(
            stream.next().await.unwrap(),
            Ok(Event::BlockBegin(_))
        ));
        tokio::time::advance(Duration::from_secs(1)).await;

        token.cancel();
        handle.await.unwrap().unwrap();

        assert!(receiver.try_recv().is_err());
    }
}
